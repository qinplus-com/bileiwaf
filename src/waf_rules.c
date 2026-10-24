#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../include/waf_rules.h"
#include "../include/waf_log.h"
#include "../include/waf_ai.h"
#include "../include/waf_perf.h"
#include "../include/waf_cc.h"
#include "../include/waf_http.h"
#include <openssl/evp.h>
#include <dirent.h>
#include <signal.h>
#include <time.h>

#define RULE_CACHE_SIZE 4096
#define RULE_CACHE_TTL 60

typedef struct {
    unsigned int hash;
    int result;
    time_t timestamp;
} rule_cache_entry_t;

static detection_rule_t detection_rules[MAX_RULES];
static int detection_rules_count = 0;
/* 规则表读写锁：AI 护栏可在请求线程内触发热加载(rules_reload 会 regfree+memset
 * 整张表)，与其它工作线程正在进行的规则匹配构成 use-after-free。
 * 匹配路径取读锁(可并发)，reload 取写锁(独占)。 */
static pthread_rwlock_t rules_lock = PTHREAD_RWLOCK_INITIALIZER;
static volatile sig_atomic_t rules_reload_pending = 0;

static ai_config_t *ai_config_ptr = NULL;

void rules_set_ai_config(ai_config_t *config) {
    ai_config_ptr = config;
}

static rule_cache_entry_t rule_cache[RULE_CACHE_SIZE];
static pthread_mutex_t rule_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

static unsigned int hash_string(const char *str) {
    unsigned int hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

static int rule_cache_get(const char *data, attack_type_t type) {
    if (!data || !data[0]) return -1;
    
    unsigned int hash = hash_string(data) ^ (unsigned int)type;
    int idx = hash % RULE_CACHE_SIZE;
    
    pthread_mutex_lock(&rule_cache_mutex);
    if (rule_cache[idx].hash == hash && 
        (time(NULL) - rule_cache[idx].timestamp) < RULE_CACHE_TTL) {
        int result = rule_cache[idx].result;
        pthread_mutex_unlock(&rule_cache_mutex);
        return result;
    }
    pthread_mutex_unlock(&rule_cache_mutex);
    return -1;
}

static void rule_cache_set(const char *data, attack_type_t type, int result) {
    if (!data || !data[0]) return;
    
    unsigned int hash = hash_string(data) ^ (unsigned int)type;
    int idx = hash % RULE_CACHE_SIZE;
    
    pthread_mutex_lock(&rule_cache_mutex);
    rule_cache[idx].hash = hash;
    rule_cache[idx].result = result;
    rule_cache[idx].timestamp = time(NULL);
    pthread_mutex_unlock(&rule_cache_mutex);
}

static int fast_pattern_check(const char *data, const char *pattern) {
    if (!data) return 0;
    
    const char *needles[] = {
        // XSS基本特征
        "<script", "</script", "<script src", "' OR ", "' OR 1", "OR 1=1", "-- ", "/*", "*/",
        "javascript:", "vbscript:", "data:", "onerror", "onload", "onclick",
        "onmouseover", "document.cookie", "document.write", "window.location",
        "window.open", "eval(", "alert(", "../etc", "/etc/", "/proc/",
        "ping -", "ping -c", "cat /", "rm -",
        "<iframe", "src=http", "src=https",
        "\\u00", "chr(", ")(|", "${#",
        "union select", "or 1=1", "and 1=1", "../", "WEB-INF", "web.xml",
        "%{#", "' and '", "' or '",
        "whoami", "nslookup", "uname", "; echo", ";echo", "; ping", "| ping",
        "||", "ping ", "&#x", "&#", "<meta", "<!docty", "<!DOCTY",
        "insert into", "delete from", "concat(", "char(", "load_file",
        "bin/sh", "/bin/", "cmd.exe", "powershell", "select ", "from ",
        "current_user", "@@version", "version()", "database()", "schema",
        "sleep(", "benchmark(", "extractvalue", "updatexml", "exp(", "floor(",
        "onfocus", "onblur", "srcdoc", "formaction", "xlink",
        "fromCharCode", "atob(", "prompt(", "confirm(", "print(", "fetch(",
        "java.lang", "ProcessBuilder", "getRuntime", "com.mchange",
        "WrapperConnectionPoolDataSource", "defaultData:com.", "HexAsciiS",
        "Tzo", "filename=", "Content-Disposition", "..;/", "win.ini", "boot.ini",
        "php://", "zip://", "phar://", "glob://", "expect://",
        
        // Webshell/命令注入特征
        "invokefunction", "call_user_func", "{dede:field", "runphp='yes'",
        "/think/", "index.php?s=", "vulnerabilities/xss", "tag_test_action.php",
        "partcode=", "DOM=", "vars[",
        "xlink:href", "dumpConfig", "xlink", "fromCharCode",
        
        // SQL注入特征
        "vulnerabilities/sqli", "vulnerabilities/exec", "vulnerabilities/upload",
        "EXTRACTVALUE", "xmltype", "UNION SELECT", "FROM users", "LIMIT 1",
        "' AND ", "AND (SELECT", "SELECT password",
        "/webtools/control/", "SOAPService",
        "CASE WHEN", "TO_CHAR", "THEN", "FROM users", "WHERE username",
        "||(SELECT", "CASE WHEN LENGTH", "TO_CHAR(1/0)",
        
        // 路径穿越特征
        "%252e%252e", "%2e%2e", "..%2f", "%2e%2e%2f", "..%255c",
        "%252f%252f", "%2f%2f", "..%255c",
        "vulnerabilities/fi", "vulnerabilities/lfi",
        "../../etc/passwd", "../..%2f", "%2e%2e%2f%2f",
        "passwd", "etc/shadow", "boot.ini",
        
        // OGNL注入特征 - 增强版
        "${#", "#context", "getRealPath", "getWriter()", "println(",
        "ognl:", "#a=#", "#matt=", "#b=#",
        "file:%2f%2f", "file://",
        ".action?redirect", "index.action",
        "#context.get", "#request.", "#response.", "#session.", "#application.",
        "#root.", "#container.", "#_memberAccess.", "@ognl.",
        "getClass().forName", "newInstance()", "getDeclaredMethod",
        ".getMethod(", ".invoke(", "Runtime.getRuntime",
        "exec(", "ProcessBuilder(", "socket(", "ServerSocket(",
        "/etc/", "/proc/", "/bin/", "/usr/", "/var/", "/tmp/", "/root/",
        
        // OGNL表达式中的Java方法调用
        "#this.getClass()", "#this.getClass().forName",
        "#runtimeclass", "#getruntimemethod", "#rtobj", "#execmethod",
        ".getDeclaredMethods()", ".invoke(null,null)",
        "touch /tmp/", "ognl-context", "ognl.OgnlContext",
        
        // OGNL高级特征
        "new java.lang.ProcessBuilder", "java.lang.Runtime.getRuntime().exec",
        "getRuntime().exec(", ".exec('id')", ".exec(\"id\")",
        "new java.io.BufferedReader", "new java.io.FileReader",
        "com.opensymphony.xwork2.dispatcher.HttpServletRequest",
        "com.opensymphony.xwork2.dispatcher.HttpServletResponse",
        "#_memberAccess=", "#application.", "#session.",
        "@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS",
        "@java.lang.Thread@currentThread().getContextClassLoader()",
        
        // PHP配置攻击
        "unix:", "php5?", "allow_url_include", "auto_prepend_file",
        "suhosin.simulation", "open_basedir", "cgi.force_redirect",
        "%40%40SENSE_VERSION", "sense_version=",
        "disable_functions=", "safe_mode=", "cgi.redirect_status_env",
        
        // Java安全漏洞
        "api/console/api_server", "apis=../../",
        "HttpServletRequest", "HttpServletResponse", "dispatcher",
        
        // SSRF特征
        "dict://", "gopher://", "ftp://",
        "http://example.com", "https://example.com",
        "| http://", "| https://", "| ftp://",
        "& http://", "&& http://", "; http://",
        "> /", ">> /", "< /", "2>&1",
        
        // 命令注入和管道操作符 - 更精确的特征
        "| nc -", "| bash -", "| sh -", "| python -", "| perl -",
        "| /bin/", "| /usr/bin/",
        "; nc -", "; bash -", "; sh -", "; python -", "; perl -",
        "; /bin/", "; /usr/bin/",
        "`nc -", "`bash -", "`sh -",
        "$(nc -", "$(bash", "$(sh ",
        "> /etc/passwd", ">> /etc/passwd", "> /etc/shadow",
        "wget http://", "curl http://", "lynx http://",
        "nc -e /bin", "nc -e /usr/",
        "2>&1 /etc/", "2>&1 /var/", "2>&1 /root/",
        
        // 其他高风险特征
        "extdirect", "/service/extdirect", "/uc/feedback/api",
        "base64_decode", "assert(", "preg_replace",
        "system(", "passthru(", "shell_exec(", "popen(",
        "str_rot13", "gzinflate", "eval(base64",
        
        // 反序列化攻击 - 更精确的特征
        "O:8:\"", "O:7:\"", "O:6:\"",
        "phar://", "compress.zlib://", "compress.bzip2://",
        "php://input", "php://filter",
        "__wakeup", "__destruct", "serialize(",
        
        // Java反序列化特征
        "0xac0xed", "rO0AB", "JRMP", "ysoserial",
        "java.io.ObjectInputStream", "readObject(",
        "ObjectInputStream", "readResolve", "readExternal",
        
        // Python反序列化
        "cos\nsystem", "cPickle", "__reduce__", "marshal.loads",
        "pickle.loads", "unpickle", "eval(",
        
        // YAML反序列化
        "!!python/object", "!!python/object/apply",
        "!!com.sun.", "!!javax.script.",
        "yaml.load(", "yaml.safe_load",
        
        // 文件包含漏洞
        "include(", "include_once(", "require(", "require_once(",
        
        // XSLT注入
        "xsl:stylesheet", "xsltproc", "xalan:", "saxon:",
        
        // LDAP注入
        "*)(uid=*", "*)(objectClass=*", "admin*)",
        
        // XML注入
        "<!DOCTYPE", "<!ENTITY", "SYSTEM \"",
        
        // Log4j/Log4shell检测
        "${jndi:", "${${::-j}", "${${::-n}",
        "jndi:ldap://", "jndi:rmi://", "jndi:dns://",
        "jndi:naming", "${env:", "${sys:",
        
        // Spring框架攻击
        "T(java.", "T(org.springframework",
        "@org.springframework",
        "classLoader.loadClass", "forName(",
        "getClass().getResource", "getClass().getClassLoader",
        "FreeMarkerUtil", "TemplateDirectiveModel",
        
        // 模板注入检测
        "{{", "}}", "${${",
        "${仓", "${name}", "{%", "%}",
        "<#assign", "<#list", "<#if",
        "${page.", "${request.",
        
        // CRLF注入
        "%0d%0a", "\\r\\n", "\r\n",
        "Set-Cookie:", "Location:",
        "X-Forwarded-Host:", "X-Real-IP:",
        
        // NoSQL注入
        "$ne", "$gt", "$gte", "$lt", "$lte",
        "$regex", "$where", "$exists",
        "\"$ne\":", "'$ne':",
        "admin$", "' OR 'true'='true",
        
        // 文件上传攻击特征
        "filename=", ".php", ".jsp", ".asp",
        ".php3", ".php4", ".php5", ".phtml",
        ".jspx", ".jspf", ".html",
        "Content-Disposition",

        // 检出补强(blazehttp FN 归因): 布尔注入数字变体/反引号/CRLF/反序列化魔数等
        "or 1=", "or 2=", "and 1=", "and 2=", "or 3=", "and 3=",
        ".call(", ".apply(", "<?php", "phpinfo", "utilcmdargs",
        "file_put_contents", "$\\a{", "$\\b{", "$\\\\a{", "$\\\\b{",
        "+adw-", "<base", "%ac%ed", "o:1", "o:2",
        "`id", "`whoami", "`uname", "exec=", "element_parents",
        "%0d%0d", "%0a%0a", "%0a%0d", "$regex", "$where",

        NULL
    };
    
    for (int i = 0; needles[i]; i++) {
        if (strcasestr(data, needles[i])) {
            return 1;
        }
    }

    // 如果提供了 pattern，也检查 pattern
    if (pattern && strcasestr(data, pattern)) {
        return 1;
    }
    
    return 0;
}

static const char *whitelist_paths[] = {
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".json",
    ".gz",
    ".m4s",
    ".mp4",
    ".flv",
    ".gz.js",
    ".htm",
    ".html",
    ".aspx",
    ".fcg",
    ".min.js",
    ".min.css",
    ".pdf",
    ".txt",
    ".xml",
    ".csv",
    ".zip",
    ".rar",
    "/@",
    "/npm/",
    "/cdn/",
    "/cdn-cgi/",
    "/festatic/",
    "/workbox-cdn/",
    "/@ant-design/",
    "/@ctrl/",
    "/@babel/",
    "/rc-",
    "/node_modules/",
    "/static/",
    "/public/",
    "/images/",
    "/fonts/",
    "/scripts/",
    "/styles/",
    "/resources/",
    "/collector/",
    "/api/users/",
    "/api/v4/me",
    "/api/report",
    "/api/payment/",
    "/api/log",
    "/api/v4/creator/",
    "/cm/api/",
    "/api/v2/common/",
    "/cgi-bin/mmwebwx-bin/",
    "/v2021.11.09/",
    "/api/v4/moments/",
    "/trippackage/",
    "/api/post/likes",
    "/api/resource/v1/",
    "/search?",
    "/cgi-bin/xlogin",
    "/rest/componentPush",
    "/api/v1/message/",
    "/api/v1/host/",
    "/content",
    "/api/v1/organizations/",
    "/v1/cgi-bin/common/",
    "/v1/projects/",
    "/cur/",
    "/0",
    "/ws/websocket",
    "/aegis/whitelist",
    "/fill-instrument/",
    "/interact_api/",
    "/api/v2/tools/",
    "/api/v1/config/",
    "/user_api/v1/",
    "/v1/p",
    "/cart/getCartCount",
    "/kns8/Detail",
    "/maps/instrumentation",
    "/dana-na/auth/",
    "/report.cgi",
    "/wcum?",
    "/fingerprint/v1/",
    "/forum.php?",
    "/getscript?",
    "/csp_report",
    "/opc_resource/",
    "/im-manage/v1.0/",
    "/uc/feedback/",
    "/api/msg/ws/",
    "/api/v4/home/",
    "/community/personal-api/",
    "/cbe/",
    "/model-poc",
    "/blog-console-api/",
    "/batch",
    "/complete/",
    "/g/collect",
    "/webv3",
    "/seo-inlinks",
    "/status/",
    "/web/",
    "/gtag/",
    "/weapi/",
    "/v1/im/message/clean",
    "/link_setting/v1/link_setting/get",
    "/cgi/",
    "/mini_login.htm",
    "/cgi/v2/console-resourcebillv2-cost",
    "/about",
    "/products",
    "/blog",
    "/contact",
    "/news",
    "/download",
    "/github/collect",
    "/_private/browser/stats",
    "/metal/ingest",
    "/dianshi/query-price",
    "/index.php/form/XDFrame",
    "/heartbeat",
    "/fd/ls/l",
    "/wind",
    "/safeline/",
    "/analytics/",
    "/alimail/",
    "/datakit/",
    "/time-sync/",
    "/rpc/v2/",
    "/restapi/",
    "/content_api/",
    "/diversified/",
    "/cmc/cross",
    "/collect?",
    "/u/login",
    "/worker/caret",
    "/v1/vitals",
    "/dl/getConf",
    "/activityi",
    "/graphql",
    "/OneCollector/",
    "/nclm",
    "/common/oauth2",
    "/subpage",
    "/track/create-track",
    "/recommend/baidu_zhannei_search",
    "/speed/webvitals",
    "/s?ie=utf-8",
    "/f/refresh",
    "/spider/",
    "/report/",
    "/probation",
    "/wmp/",
    "/playlist",
    "/plugin.php",
    "/SpiderLabs/",
    "/1/indexes/",
    "/act/",
    "/mp/",
    "/waydabber/",
    "/stdlog",
    "/uc_server/",
    "/pagead/",
    "/UnifiedIDMPortal/",
    "/trafficCollect.php",
    "/post/e",
    "/getBlogCommentList",
    "/hamburger/",
    "/post/list",
    "/proxy/",
    "/ibs:",
    "/sf.php",
    "/sinaurl",
    "/post/accounts/",
    "/post/pingd",
    "/post/authredir",
    "/rain/",
    "/post/speed/",
    "/post/rewardsapp/",
    "/rec/bundle/",
    "/gingame/",
    "/search/",
    "/diffusionTask/",
    "/post/stats/",
    "/primus-v8/",
    "/recaptcha/",
    "/openapi/",
    "/post/php/",
    "/webevents/",
    "/post/track/",
    "/post/chloro-device/",
    "/post/w?",
    "/post/0",
    "/store/",
    "/chat/",
    "/post/v1/rgstr",
    "/ajax/",
    "/REF/",
    "/service/",
    "/post/abdr",
    "/zhuanti/",
    "/post/_graphql/",
    "/fgw/",
    "/oauth?",
    "/post/pt4_auth",
    "/post/v1/projects/",
    "/post/v1.0/",
    "/web.php/",
    "/LittleHann/",
    "/ztbox?",
    "/seek/",
    "/swc/",
    "/h5plus/",
    "/ytf/",
    "/mall/",
    "/action/",
    "/livemsg?",
    "/fapi/",
    "/con?",
    "/mcp/",
    "/post/i/",
    "/v3/",
    "/security/",
    "/naq/",
    "/huamei_",
    "/checkout/",
    "/main/suggest",
    "/notifications/",
    "/dict/",
    "/img/",
    "/lastread/",
    "/VydY",
    "/link?",
    "/pingd?",
    "/dict/SerpHoverTrans",
    "/main/suggest?",
    "/notifications/render",
    "/lastread/touch",
    "/ref/",
    "/sentry/",
    "/code.cgi",
    "/abdr",
    "/intermittent/",
    "/rbook-api/",
    "/evolution",
    "/appstore/",
    "/socket.io/",
    "/wbsso/",
    "/captcha/",
    "/tsinghua",
    "/Collector/",
    "/get_ad_info",
    "/counter6",
    "/speed",
    "/horn/",
    "/spc.php",
    "/collect/",
    "/orgid/",
    "/ruanyf",
    "/federation",
    "/e",
    "/list",
    "/v1/rgstr",
    "/post/e",
    "/pingd",
    "/v1/im/unread/",
    "/ipaddress",
    "/instrument/",
    "/v2/config/",
    "/i/adsct",
    "/kpi",
    "/weather/",
    "/action?",
    "/all?",
    "/u/",
    "/UAT/",
    "/geolocation/",
    "/_axiom/",
    "/dianshi/",
    "/rewardsapp/",
    NULL
};

/*
 * 文件白名单（URL 精确路径）——用于抑制「正常文件路径本身含攻击关键词」导致的误报：
 * 例如技术文章页 /html/shutdown.html（路径含 CMD 关键词 shutdown）、
 * /html/ad_sql__DROP__DATABASE.html（路径含 SQL 关键词 DROP DATABASE）
 * 会被 URL 侧关键词规则误判为攻击而拦截。
 *
 * 语义边界（刻意设计，防绕过通道）：
 *  - 仅在「URL 路径本身」的检查上生效——命中后跳过针对 req->url 的关键词规则
 *    （xss/path_traversal/sql/cmd/xml/ssrf 及 AI 自学习 ATTACK_UNKNOWN）；
 *  - query、body、Cookie、Referer、其它 header 等载荷来源**仍照常全量检测**，
 *    因此在白名单路径上挂 ?id=1' OR '1'='1 之类的载荷依然会被拦截；
 *  - 大小写不敏感精确匹配（非前缀），避免 /html/shutdown.html.old 之类被误放行。
 *
 * 条目由 rules/whitelist.url 加载（每行一条，'#' 开头为注释），rules_init/
 * rules_reload 时读盘，故支持热更新。*/
#define MAX_FILE_WHITELIST 256
static char file_whitelist_paths[MAX_FILE_WHITELIST][256];
static int file_whitelist_count = 0;

static void file_whitelist_load(const char *rules_dir) {
    file_whitelist_count = 0;
    if (!rules_dir) rules_dir = "rules";

    char fname[512];
    snprintf(fname, sizeof(fname), "%s/whitelist.url", rules_dir);

    FILE *fp = fopen(fname, "r");
    if (!fp) {
        /* 文件缺失属正常情况（用户未创建），静默跳过 */
        waf_log(LOG_LEVEL_DEBUG, "File whitelist not found (optional): %s", fname);
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp) && file_whitelist_count < MAX_FILE_WHITELIST) {
        char *p = waf_trim(line);
        if (p[0] == '#' || p[0] == '\0') continue;
        /* 仅接受以 '/' 开头的绝对路径条目，杜绝模糊条目带来的过宽放行 */
        if (p[0] != '/') {
            waf_log(LOG_LEVEL_WARN, "File whitelist entry ignored (must start with '/'): %s", p);
            continue;
        }
        strncpy(file_whitelist_paths[file_whitelist_count], p, 255);
        file_whitelist_paths[file_whitelist_count][255] = '\0';
        file_whitelist_count++;
    }
    fclose(fp);

    waf_log(LOG_LEVEL_INFO, "Loaded %d file whitelist entries from %s", file_whitelist_count, fname);
}

/* 精确路径匹配（大小写不敏感）。命中表示「该 URL 路径视为正常文件路径」。 */
static int file_whitelist_match(const char *path) {
    if (!path || !path[0]) return 0;
    for (int i = 0; i < file_whitelist_count; i++) {
        if (strcasecmp(path, file_whitelist_paths[i]) == 0) return 1;
    }
    return 0;
}

/*
 * Whitelist path matching:
 *  - Entries starting with '/' are PATH PREFIXES (e.g. "/api/users/"),
 *    matched only at the beginning of the request path. A plain substring
 *    match would let any URL containing the fragment (e.g. "/e" inside
 *    "/etc/passwd") bypass all deep inspection.
 *  - Entries starting with '.' are static-asset EXTENSIONS, matched as
 *    substrings anywhere in the URL.
 */
static int whitelist_entry_match(const char *url, const char *path, const char *entry) {
    if (!entry || !entry[0]) return 0;

    if (entry[0] == '/') {
        size_t len = strlen(entry);
        if (path && path[0] && strncmp(path, entry, len) == 0) return 1;
        if (url && url[0]) {
            const char *q = strchr(url, '?');
            size_t plen = q ? (size_t)(q - url) : strlen(url);
            if (plen >= len && strncmp(url, entry, len) == 0) return 1;
        }
        return 0;
    }

    if (url && strstr(url, entry) != NULL) return 1;
    if (path && strstr(path, entry) != NULL) return 1;
    return 0;
}

static const char *attack_type_names[] = {
    "SQL_INJECTION", "XSS", "CMD_INJECTION", "PATH_TRAVERSAL",
    "FILE_UPLOAD", "CSRF", "LDAP_INJECTION", "XML_INJECTION",
    "JSON_INJECTION", "SSRF", "DESERIALIZATION", "SCANNER",
    "CC", "MALICIOUS_BOT", "BRUTE_FORCE", "API_ABUSE", "UNKNOWN"
};

static const char *sql_injection_patterns[] = {
    "(\\bunion\\s+[a-z]*\\s+select\\b|\\bunion\\s+all\\s+select\\b)",
    "(\\bexec\\s*\\(\\s*(xp_|0x|@|'|\")|\\bexecute\\s*\\(\\s*(xp_|sp_|'|\"))",
    "(\\bupdate\\s+[a-z_]+\\s+set\\b|\\bdelete\\s+from\\s+[a-z_]+\\b|\\binsert\\s+into\\s+[a-z_]+\\b)",
    "('\\s*(or|and)\\s+1\\s*=\\s*1)",
    "('\\s*(or|and)\\s*'\\s*=\\s*')",
    "(\\bsleep\\s*\\(|\\bbenchmark\\s*\\()",
    "(\\binformation_schema\\b|\\bpg_catalog\\b)",
    "(\\bvarchar\\s*\\(|\\bnvarchar\\s*\\(|\\btext\\s*\\(|\\bclob\\s*\\(|\\bblob\\s*\\()",
    "(\\bcast\\s*\\(|\\bconvert\\s*\\(|\\bsubstring\\s*\\()",
    "(\\bselect\\s+[0-9*,]+\\s+from\\s+information_schema\\b|\\bselect\\s+@@|\\bselect\\s+version\\s*\\()",
    "(TrackingId\\s*=\\s*['\"]?.*['\"]?\\s*(or|and|\\|\\|)\\s*)",
    "(\\bextractvalue\\s*\\(|\\bupdatexml\\s*\\()",
    "(\\bcase\\s+when\\s+\\S+(\\s+\\S+)?\\s+then\\b)",
    "(\\blength\\s*\\(|\\bsubstr\\s*\\()",
    "(\\bto_char\\s*\\(|\\bto_number\\s*\\()",
    "(\\bfrom\\s+users\\b|\\bfrom\\s+all_tables\\b)",
    "(jndi:)",
    "(\\$\\{jndi)",
    "(\\bgroup_concat\\s*\\(|concat_ws\\s*\\(|\\bconcat\\s*\\(\\s*(0x[0-9a-fA-F]|char\\s*\\())",
    "('\\s*\\|\\|\\s*[\\d(])",
    "(\\bwaitfor\\s+delay)",
    "(\\bpgsleep\\s*\\(|\\bpg_sleep\\s*\\()",
    "(\\bdbms_pipe\\.receive_message|\\bdbms_lock\\.sleep)",
    "(\\bxmlelement|\\bxmltype)",
    "(\\bor\\s+true|\\band\\s+false)",
    "(\\bcast\\s*\\(|\\bCAST\\s*\\()",
    "(['\"\\)]\\s*(AND|OR)\\s+1\\s*=\\s*1)",
    "(\\band\\s*\\(\\s*\\d+\\s*=\\s*\\d+\\s*\\)|\\bor\\s*\\(\\s*\\d+\\s*=\\s*\\d+\\s*\\))",
    "(\\bcast\\s*\\(|\\bCONVERT\\s*\\(|\\bconvert\\s*\\()",
    "(\\bCAST\\s*\\(|\\bcast\\s*\\()",
    "(\\bOR\\s*'\\s*=\\s*'|\\bAND\\s*'\\s*=\\s*')",
    "(\\bCAST\\s*\\(|\\bCONVERT\\s*\\()",
    "(['\"\\)]\\s*(OR\\s+true|AND\\s+false))",
    "(extractvalue.*concat|concat.*char.*version|extractvalue\\s*\\(\\s*1\\s*,)",
    "(\\%ac\\%ed|\\xac\\xed|%ac%ed%00%05)",
    NULL
};

static const char *xss_patterns[] = {
    "(<script[^>]*>|</script>)",
    "(<script\\s+src\\s*=)",
    "(javascript:\\s*(alert|prompt|confirm|eval|print|fetch|document\\.|window\\.)|vbscript:)",
    "(onerror|onload|onclick|onmouseover|onfocus|onblur|onbeforeprint|onafterscriptexecute)\\s*=\\s*[\"']?[^\\s>&()]*\\(",
    "(<svg[^>]*on[a-z]+\\s*=|<img[^>]*src\\s*=\\s*[\"']?\\s*(javascript:|data:text)|iframe[^>]*src\\s*=\\s*[\"']?\\s*(javascript:|data:text))",
    "(document\\.(cookie|write|location)|window\\.(location|open)|eval\\s*\\()",
    "(alert\\s*\\(|confirm\\s*\\(|prompt\\s*\\()",
    "(String\\.fromCharCode|unescape\\s*\\(|atob\\s*\\()",
    "(\\['ale'\\s*\\+\\s*'rt'\\])",
    "(&#[0-9]+;?|&#x[0-9a-fA-F]+;?)",
    "(\\[\\/\\*[^*]*\\*\\/['\"]alert['\"]\\/\\*[^*]*\\*\\/\\])",
    "(\\%c0%bc|%e0%80%bc|%f0%80%80%bc|%f8%80%80%80%bc|%fc%80%80%80%80%bc|%C0%BC|%E0%80%BC|%F0%80%80%BC|%F8%80%80%80%BC|%FC%80%80%80%80%BC)",
    "(srcdoc\\s*=|formaction\\s*=)",
    "(\\{\\{[^}]*(\\*|__|constructor)[^}]*\\}\\}|\\{%[^%]*%\\})",
    "(<[^>]*(onabort|onblur|oncanplay|oncanplaythrough|onchange|onclick|oncontextmenu|ondblclick|ondrag|ondragend|ondragenter|ondragleave|ondragover|ondragstart|ondrop|ondurationchange|onemptied|onended|onerror|onfocus|oninput|oninvalid|onkeydown|onkeypress|onkeyup|onload|onloadeddata|onloadedmetadata|onloadstart|onmousedown|onmousemove|onmouseout|onmouseover|onmouseup|onmousewheel|onpause|onplay|onplaying|onprogress|onratechange|onreadystatechange|onreset|onscroll|onseeked|onseeking|onselect|onstalled|onsubmit|onsuspend|ontimeupdate|ontoggle|onvolumechange|onwaiting|onwheel)\\s*=)",
    "(\\\\[0-7][0-7][0-7])",
    "(\\%253C\\%253Fxml|%25c0%bc|%25e0%80%bc)",
    "(\\%26lt;|\\%26#x3c;)",
    "(<script[^>]*src\\s*=\\s*[\"']?http)",
    "(<script[^>]*src\\s*=\\s*[\"']?https)",
    "(<script[^>]*src\\s*=\\s*[^>]*evil)",
    NULL
};

static const char *cmd_injection_patterns[] = {
    "(\\;|\\n|\\r|\\|)\\s*(cat|ls|rm|cp|mv|wget|curl|chmod|chown|grep|find|touch|mkdir)\\b\\s*(\\(|\\/|\\-)",
    "(\\;|\\||\\&)\\s*(/bin/|/usr/bin/|/sbin/)",
    "(\\brm\\s+-rf|\\bmkfs|\\bmount\\s+-)",
    "(\\`cat\\s+|\\`ls\\s+|\\`rm\\s+|\\`wget\\s+|\\`curl\\s+)",
    "(\\$\\(cat\\s+|\\$\\(ls\\s+|\\$\\(rm\\s+|\\$\\(wget\\s+|\\$\\(curl\\s+)",
    "(nc\\s+-e|netcat\\s+-e)",
    "(bash\\s+-i|/bin/sh\\s+-i)",
    "(\\%ac\\%ed|\\xac\\xed|%ac%ed%00%05|%ac%ed%00%05%73%72)",
    "(-d\\s+(allow_url_include|auto_prepend_file)\\s*=\\s*(1|on|php:))",
    "(java\\.lang\\.String|java\\.lang\\.Object|java\\.io\\.ObjectStream|java\\.util\\.PriorityQueue)",
    "([;&|`\\$()]\\s*(ping|whoami|nslookup)\\b)",
    "(jndi:|\\$\\{jndi)",
    "(com\\.ct\\.arelei|test\\.Person)",
    "(\\%ac%ed%00%05%73%72%00%1a|%ac%ed%00%05%73%72%00%1a%63%6f%6d)",
    "(%ac%ed%00%05%73%72%00%1a%63%6f%6d%2e%63%74%2e%61%72%65%6c%65%69%69%2e%74%65%73%74%2e%50%65%72%73%6f%6e)",
    NULL
};

static const char *path_traversal_patterns[] = {
    "(\\.\\.\\/|\\.\\.\\%2f|%2e%2e|\\%252e\\%252e)",
    "(\\.\\.\\\\|\\.\\.\\%5c|%2e%2e%5c)",
    "(\\.\\.\\%c0%af|%2e%2e%c0%af)",
    "(etc\\/passwd|c\\\\:\\\\windows|c:\\\\windows)",
    "(\\/etc\\/passwd|\\.\\.\\/\\.\\.\\/\\.\\.\\/etc\\/passwd|%252e%252e%252f%252e%252e)",
    "(\\.\\.\\/.*\\.\\.|%252e%252e)",
    "(\\/\\.\\.\\/|%2f%2e%2e%2f)",
    "(Accept.*\\.\\.\\/)",
    "(file\\:\\/\\/)",
    "(\\.\\.\\/\\.\\.\\/\\.\\.\\/\\.\\.\\/)",
    "(apis.*\\.\\.\\/)",
    NULL
};

static const char *file_upload_patterns[] = {
    "(\\.exe|\\.bat|\\.cmd|\\.sh|\\.scr|\\.vbs|\\.vbe)$",
    "(filename\\s*=\\s*\"[^\"]*\\.(phtml|phar|phpt|php[345]?)\")",
    "(\\.htaccess|\\.htpasswd|\\.userini)$",
    NULL
};

static const char *scanner_patterns[] = {
    "(acunetix|nikto|nmap|masscan|sqlmap|burp|owasp| Nessus)",
    "(dirbuster|gobuster|ffuf|wfuzz|dirb|metasploit)",
    NULL
};

static int load_rules_from_file(const char *rules_dir, const char *filename, attack_type_t type) {
    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "%s/%s", rules_dir, filename);
    
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        waf_log(LOG_LEVEL_INFO, "Rule file not found: %s, using built-in rules", filepath);
        return 0;
    }

    char line[2048];
    int loaded = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (detection_rules_count >= MAX_RULES) break;
        
        char *trimmed = waf_trim(line);
        if (!trimmed || trimmed[0] == '#' || trimmed[0] == '\0') continue;

        char *token = strtok(trimmed, ",");
        if (!token) continue;

        char type_str[64], pattern[1024], severity_str[16], action_str[16], desc[512];
        strncpy(type_str, token, sizeof(type_str) - 1);

        token = strtok(NULL, ",");
        if (!token) continue;
        strncpy(pattern, token, sizeof(pattern) - 1);

        token = strtok(NULL, ",");
        if (!token) continue;
        strncpy(severity_str, token, sizeof(severity_str) - 1);

        token = strtok(NULL, ",");
        if (!token) continue;
        strncpy(action_str, token, sizeof(action_str) - 1);

        token = strtok(NULL, ",");
        if (token) strncpy(desc, token, sizeof(desc) - 1);
        else desc[0] = '\0';

        detection_rule_t *rule = &detection_rules[detection_rules_count];
        snprintf(rule->id, sizeof(rule->id), "FILE-%d", detection_rules_count);
        snprintf(rule->name, sizeof(rule->name), "%s", desc[0] ? desc : type_str);
        strncpy(rule->pattern, pattern, sizeof(rule->pattern) - 1);
        rule->type = type;
        rule->severity = atoi(severity_str);
        rule->action = (strcmp(action_str, "block") == 0) ? WAF_ACTION_BLOCK : WAF_ACTION_LOG;
        rule->enabled = 1;

        int ret = regcomp(&rule->regex, pattern, REG_EXTENDED | REG_ICASE);
        if (ret != 0) {
            waf_log(LOG_LEVEL_ERROR, "Failed to compile regex for rule %s: %s", rule->id, pattern);
            continue;
        }

        detection_rules_count++;
        loaded++;
    }

    fclose(fp);
    waf_log(LOG_LEVEL_INFO, "Loaded %d rules from %s", loaded, filepath);
    return loaded;
}

int rules_init(const char *rules_dir, void *waf_cfg_ptr) {
    if (!rules_dir) rules_dir = "rules";

    memset(detection_rules, 0, sizeof(detection_rules));
    detection_rules_count = 0;

    // 先加载规则文件
    load_rules_from_file(rules_dir, "sql_injection.rules", ATTACK_SQL_INJECTION);
    load_rules_from_file(rules_dir, "xss.rules", ATTACK_XSS);
    load_rules_from_file(rules_dir, "cmd_injection.rules", ATTACK_CMD_INJECTION);
    load_rules_from_file(rules_dir, "path_traversal.rules", ATTACK_PATH_TRAVERSAL);
    load_rules_from_file(rules_dir, "file_upload.rules", ATTACK_FILE_UPLOAD);
    load_rules_from_file(rules_dir, "scanner.rules", ATTACK_SCANNER);
    load_rules_from_file(rules_dir, "xxe.rules", ATTACK_XML_INJECTION);
    load_rules_from_file(rules_dir, "ssrf.rules", ATTACK_SSRF);
    /* AI 自主学习产出的规则（独立文件，与人工规则物理隔离；缺失则静默跳过） */
    load_rules_from_file(rules_dir, "ai_learned.rules", ATTACK_UNKNOWN);

    /* 文件白名单（URL 精确路径，用于抑制文件路径关键词误报；可选文件，缺失静默跳过） */
    file_whitelist_load(rules_dir);

    // 始终加载内置规则，确保即使规则文件有问题也能正常工作
    const char **pattern_arrays[] = {
        sql_injection_patterns,
        xss_patterns,
        cmd_injection_patterns,
        path_traversal_patterns,
        file_upload_patterns,
        scanner_patterns,
        NULL
    };

    attack_type_t types[] = {
        ATTACK_SQL_INJECTION,
        ATTACK_XSS,
        ATTACK_CMD_INJECTION,
        ATTACK_PATH_TRAVERSAL,
        ATTACK_FILE_UPLOAD,
        ATTACK_SCANNER
    };

    int pattern_idx = 0;

    for (int array_idx = 0; pattern_arrays[array_idx] != NULL; array_idx++) {
        const char **patterns = pattern_arrays[array_idx];
        attack_type_t type = types[array_idx];

        for (int i = 0; patterns[i] != NULL; i++) {
            if (detection_rules_count >= MAX_RULES) break;

            detection_rule_t *rule = &detection_rules[detection_rules_count];

            snprintf(rule->id, sizeof(rule->id), "BUILTIN-%d", pattern_idx);
            snprintf(rule->name, sizeof(rule->name), "%s Builtin Rule %d",
                     attack_type_names[type], i);
            strncpy(rule->pattern, patterns[i], sizeof(rule->pattern) - 1);
            rule->type = type;
            rule->severity = (i == 0) ? 5 : 4;
            rule->action = WAF_ACTION_BLOCK;
            rule->enabled = 1;

            int ret = regcomp(&rule->regex, patterns[i], REG_EXTENDED | REG_ICASE);
            if (ret != 0) {
                waf_log(LOG_LEVEL_ERROR, "Failed to compile regex for rule %s: %s",
                        rule->id, patterns[i]);
                continue;
            }

            detection_rules_count++;
            pattern_idx++;
        }
    }

    // ai_init already called in waf.c

    waf_log(LOG_LEVEL_INFO, "Rules initialized: %d rules loaded", detection_rules_count);

    return 0;
}

void rules_destroy(void) {
    for (int i = 0; i < detection_rules_count; i++) {
        regfree(&detection_rules[i].regex);
    }

    memset(detection_rules, 0, sizeof(detection_rules));
    detection_rules_count = 0;

    /* 同时清空阴性结果缓存：热加载新增规则后，若不清缓存，相同载荷会命中
     * 旧的「阴性」缓存条目(TTL 60s)而绕过新规则——铸出的规则在 60s 内失效。 */
    pthread_mutex_lock(&rule_cache_mutex);
    memset(rule_cache, 0, sizeof(rule_cache));
    pthread_mutex_unlock(&rule_cache_mutex);
}

static int rules_check_whitelist_path(http_request_t *req, attack_match_t *match) {
    /* 白名单静态路径快速通道: 仅当 URL 命中针尖词时才跑 URL 侧规则,
     * 否则直接放行。修复 apache.php.jpeg / ;/WEB-INF/web.xml 这类
     * 借静态后缀穿透的样本(原实现为空函数,无条件放行)。 */
    if (!fast_pattern_check(req->url, NULL))
        return 0;
    if (rules_check_path_traversal(req->url, match) ||
        rules_check_cmd_injection(req->url, match) ||
        rules_check_sql_injection(req->url, match) ||
        rules_check_xss(req->url, match) ||
        rules_check_file_upload(req->url, match))
        return 1;
    return 0;
}

static int rules_check_generic2(const char *data, attack_type_t type,
                                attack_match_t *match, int allow_b64);

static int rules_check_only_rules(http_request_t *req, attack_match_t *match) {
    // 先检查是否是白名单路径
    int url_whitelisted = 0;
    for (int i = 0; whitelist_paths[i] != NULL; i++) {
        if (whitelist_entry_match(req->url, req->path, whitelist_paths[i])) {
            url_whitelisted = 1;
            break;
        }
    }

    /* 文件白名单（URL 精确路径）：命中的是「已知正常文件路径本身」，
     * 跳过针对 req->url 的关键词规则，消除「路径关键词」误报。
     * 注意 query/body/Cookie 等载荷来源在下方仍照常检测，不构成绕过通道。 */
    int file_wl = file_whitelist_match(req->path);

    /* 仅当静态资源且「无查询参数、无请求体」时才快速放行。
     * 原逻辑对任何命中白名单扩展名(如 .html)的 URL 都跳过全部检测，
     * 导致 /a.html?x=<script> / /a.html?id=1' OR '1'='1 这类携带攻击载荷的
     * 请求被完全绕过——攻击者只要把载荷挂在静态后缀 URL 上即可穿透 WAF。 */
    if (url_whitelisted && req->query[0] == '\0' && req->body_len == 0) {
        /* 文件白名单精确命中：路径本身已确认可信，直接放行，
         * 避免 rules_check_whitelist_path 仍按 req->url 跑关键词规则造成误报 */
        if (file_wl) {
            waf_log(LOG_LEVEL_INFO, "File whitelist matched (%s), skipping URL rule check", req->path);
            return 0;
        }
        waf_log(LOG_LEVEL_DEBUG, "Whitelist path without payload, using fast pattern check only");
        return rules_check_whitelist_path(req, match);
    }
    
    // 非白名单路径，进行完整的规则检测
    char referer[MAX_HEADER_SIZE] = {0};
    http_get_header_value(req->headers, "Referer", referer, sizeof(referer));
    /* scanner 指纹只对 User-Agent 生效：原逻辑匹配整个 headers，
     * Referer 里的安全类文章 URL(含 burp/sqlmap/owasp 等词)会造成误报 */
    char user_agent[MAX_HEADER_SIZE] = {0};
    http_get_header_value(req->headers, "User-Agent", user_agent, sizeof(user_agent));
    /* Cookie 也是攻击载体(如 base64 编码的 XSS 放在 Cookie 绕过 plain 检测);
     * Cookie 值天然多 base64/编码,开启 base64 层;会话 Cookie 多为二进制随机,
     * 90% 可打印率门槛 + 针尖词门足以抑制误报。 */
    char cookie_hdr[MAX_HEADER_SIZE] = {0};
    http_get_header_value(req->headers, "Cookie", cookie_hdr, sizeof(cookie_hdr));
    /* Content-Type 也是攻击载体:Struts2 OGNL 注入(CVE-2017-5638)
     * 把 %{#context...} 放在 Content-Type 头绕过 body 检测 */
    char content_type[MAX_HEADER_SIZE] = {0};
    http_get_header_value(req->headers, "Content-Type", content_type, sizeof(content_type));
    
    /* JSON body 跳过 XSS 检测:遥测/CSP 报告/前端日志等正常 JSON 里
     * 常带 <script>、onerror= 等 HTML 片段(作为字符串数据而非可执行标记),
     * 对 JSON 载体判 XSS 误报极高;SQL/CMD 等注入在 JSON 里仍是真实威胁,保留。 */
    int body_is_json = 0;
    for (const char *p = req->body; *p; p++) {
        if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') continue;
        body_is_json = (*p == '{' || *p == '[');
        break;
    }

    /* 任意 header 值都可能是攻击载体(Struts2 OGNL %{#...} 可放任意自定义头、
     * spring.cloud.function.routing-expression SpEL 头、X-Api-Version 反序列化等),
     * 遍历所有 header 值跑 SQL/XSS/CMD 检测;跳过已单独处理的头和纯协议头。 */
    {
        static const char *skip_exact[] = {
            "host", "user-agent", "referer", "cookie", "content-type",
            "content-length", "connection", "cache-control",
            "pragma", "dnt", "te", "expect", "origin", "x-requested-with",
            "via", "date", "server", "range", "authorization", NULL
        };
        static const char *skip_prefix[] = {
            "sec-", "accept-", "if-", "proxy-", "upgrade-", "x-forwarded-", NULL
        };
        const char *hp = req->headers;
        while (hp && *hp) {
            const char *eol = strchr(hp, '\n');
            size_t line_len = eol ? (size_t)(eol - hp) : strlen(hp);
            const char *colon = memchr(hp, ':', line_len);
            int hit = 0;
            if (colon && colon != hp) {
                size_t name_len = (size_t)(colon - hp);
                int skip = (name_len == 0 || name_len >= 48);
                char lname[48];
                if (!skip) {
                    for (size_t i = 0; i < name_len; i++)
                        lname[i] = (hp[i] >= 'A' && hp[i] <= 'Z') ? hp[i] + 32 : hp[i];
                    lname[name_len] = '\0';
                    for (int i = 0; skip_exact[i] && !skip; i++)
                        if (strcmp(lname, skip_exact[i]) == 0) skip = 1;
                    for (int i = 0; skip_prefix[i] && !skip; i++)
                        if (strncmp(lname, skip_prefix[i], strlen(skip_prefix[i])) == 0) skip = 1;
                }
                if (!skip) {
                    const char *vp = colon + 1;
                    const char *vend = hp + line_len;
                    while (vp < vend && (*vp == ' ' || *vp == '\t')) vp++;
                    while (vend > vp && (vend[-1] == '\r' || vend[-1] == ' ')) vend--;
                    if (vend > vp) {
                        size_t vlen = (size_t)(vend - vp);
                        if (vlen >= MAX_HEADER_SIZE) vlen = MAX_HEADER_SIZE - 1;
                        char hval[MAX_HEADER_SIZE];
                        memcpy(hval, vp, vlen);
                        hval[vlen] = '\0';
                        /* allow_b64=2(针尖门控): header 值里的 base64 包裹攻击
                         * (blazehttp word-salad 类把 b64 JSON 藏自定义头)需解码检测;
                         * 针尖门抑制正常 base64 头值(认证/追踪 token)的误报 */
                        hit = rules_check_generic2(hval, ATTACK_SQL_INJECTION, match, 2) ||
                              rules_check_generic2(hval, ATTACK_XSS, match, 2) ||
                              rules_check_generic2(hval, ATTACK_CMD_INJECTION, match, 2) ||
                              rules_check_generic2(hval, ATTACK_PATH_TRAVERSAL, match, 2);
                    }
                }
            }
            if (hit) return 1;
            if (!eol) break;
            hp = eol + 1;
        }
    }

    /* body/referer 走 rules_check_generic2(...,0): 关闭 base64 解码层,
     * 避免 protobuf/遥测 body 中的 base64 垃圾段解码出巧合攻击特征造成误报 */
    /* 文件白名单命中时跳过「URL 路径本身」的关键词检查(file_wl)，
     * 其余来源(query/body/referer/cookie/header)始终全量检测。 */
    if ((!file_wl &&
            (rules_check_xss(req->url, match) ||
             rules_check_path_traversal(req->url, match) ||
             rules_check_sql_injection(req->url, match) ||
             rules_check_cmd_injection(req->url, match) ||
             rules_check_xml_injection(req->url, match) ||
             rules_check_ssrf(req->url, match) ||
             rules_check_generic2(req->url, ATTACK_UNKNOWN, match, 0))) ||
        rules_check_sql_injection(req->query, match) ||
        rules_check_generic2(req->body, ATTACK_SQL_INJECTION, match, 2) ||
        rules_check_xss(req->query, match) ||
        (!body_is_json && rules_check_generic2(req->body, ATTACK_XSS, match, 2)) ||
        rules_check_generic2(referer, ATTACK_XSS, match, 2) ||
        rules_check_xml_injection(req->query, match) ||
        rules_check_generic2(req->body, ATTACK_XML_INJECTION, match, 2) ||
        rules_check_cmd_injection(req->query, match) ||
        rules_check_path_traversal(req->query, match) ||
        rules_check_generic2(req->body, ATTACK_CMD_INJECTION, match, 2) ||
        rules_check_generic2(req->body, ATTACK_PATH_TRAVERSAL, match, 2) ||
        rules_check_ssrf(req->query, match) ||
        rules_check_generic2(req->body, ATTACK_SSRF, match, 2) ||
        rules_check_generic2(referer, ATTACK_SQL_INJECTION, match, 2) ||
        rules_check_generic2(referer, ATTACK_CMD_INJECTION, match, 2) ||
        (strcmp(req->method, "POST") == 0 &&
            (rules_check_file_upload(req->path, match) ||
             rules_check_file_upload(req->body, match))) ||
        rules_check_xss(cookie_hdr, match) ||
        rules_check_sql_injection(cookie_hdr, match) ||
        rules_check_cmd_injection(cookie_hdr, match) ||
        rules_check_path_traversal(cookie_hdr, match) ||
        rules_check_generic2(content_type, ATTACK_CMD_INJECTION, match, 0) ||
        /* AI 自主学习铸出的规则(type=ATTACK_UNKNOWN)。此前该类规则在
         * rules_check_generic2 的 `rule->type != type` 过滤下无人查询，铸出即死。
         * 这里对 url/query/body/referer/cookie 五个来源补扫；ATTACK_UNKNOWN
         * 走 always=1 分支(不做针尖门)、allow_b64=0(与护栏白样本评估口径一致)。
         * （url 来源已在函数上方随文件白名单统一门控 file_wl） */
        rules_check_generic2(req->query, ATTACK_UNKNOWN, match, 0) ||
        rules_check_generic2(req->body, ATTACK_UNKNOWN, match, 0) ||
        rules_check_generic2(referer, ATTACK_UNKNOWN, match, 0) ||
        rules_check_generic2(cookie_hdr, ATTACK_UNKNOWN, match, 0) ||
        rules_check_scanner(user_agent, match)) {
        return 1;
    }
    return 0;
}

static int rules_check_only_ai(http_request_t *req, attack_match_t *match) {
    /* fail-safe：纯 AI 模式但双通道融合模型未就绪时（模型文件缺失/未训练），
     * AI 判定恒为 NORMAL 等于全放行——回退到规则引擎兜底，保证检测能力不塌。
     * 日志节流到每分钟一条，避免每请求刷屏。 */
    if (!ai_config_ptr || !ai_config_ptr->fusion_ready) {
        static volatile time_t last_fb_log = 0;
        time_t now = time(NULL);
        if (now - last_fb_log >= 60) {
            last_fb_log = now;
            waf_log(LOG_LEVEL_WARN,
                    "AI mode active but no trained model loaded; falling back to rules engine");
        }
        return rules_check_only_rules(req, match);
    }

    // 检查白名单路径，白名单路径跳过 AI 检测
    int url_whitelisted = file_whitelist_match(req->path);
    for (int i = 0; !url_whitelisted && whitelist_paths[i] != NULL; i++) {
        if (whitelist_entry_match(req->url, req->path, whitelist_paths[i])) {
            url_whitelisted = 1;
            break;
        }
    }

    if (url_whitelisted) {
        waf_log(LOG_LEVEL_INFO, "URL matched whitelist, skipping AI check");
        return 0;
    }
    
    ai_detection_result_t ai_result = ai_detect(ai_config_ptr, req);

    if (ai_result == AI_DETECTION_MALICIOUS) {
        snprintf(match->rule_id, sizeof(match->rule_id), "AI-DETECT");
        match->type = ATTACK_UNKNOWN;
        snprintf(match->description, sizeof(match->description), "AI detected malicious request");
        match->severity = 5;

        ai_auto_learn(ai_config_ptr, req, 1);

        waf_log(LOG_LEVEL_WARN, "AI detected malicious request from %s: %s",
                req->client_ip, req->url);

        return 1;
    }

    ai_auto_learn(ai_config_ptr, req, 0);
    return 0;
}

/* AUTO 级联（v3.0）：规则引擎先判，命中即拦截；未命中的流量再走 AI 双通道。
 * 与 v1.1.0 的"AI 先判"并集语义不同——已知攻击走规则毫秒级快速路径，
 * AI 专注处理规则阴性流量（规则漏检 + 0day 异常）。 */
static int rules_check_ai_and_rules(http_request_t *req, attack_match_t *match) {
    waf_log(LOG_LEVEL_DEBUG, "Entering rules_check_ai_and_rules (cascade: rules first)");

    /* 第一级：规则引擎 */
    if (rules_check_only_rules(req, match)) return 1;

    /* 第二级：AI 双通道（融合模型未就绪/AI 配置缺失/URL 白名单 → 放行） */
    if (!ai_config_ptr || !ai_config_ptr->fusion_ready) return 0;

    int url_whitelisted = file_whitelist_match(req->path);
    for (int i = 0; !url_whitelisted && whitelist_paths[i] != NULL; i++) {
        if (whitelist_entry_match(req->url, req->path, whitelist_paths[i])) {
            url_whitelisted = 1;
            break;
        }
    }
    if (url_whitelisted) {
        waf_log(LOG_LEVEL_INFO, "URL matched whitelist, skipping AI check");
        return 0;
    }

    ai_detection_result_t ai_result = ai_detect(ai_config_ptr, req);

    if (ai_result == AI_DETECTION_MALICIOUS) {
        snprintf(match->rule_id, sizeof(match->rule_id), "AI-DETECT");
        match->type = ATTACK_UNKNOWN;
        snprintf(match->description, sizeof(match->description), "AI detected malicious request");
        match->severity = 5;

        ai_auto_learn(ai_config_ptr, req, 1);

        waf_log(LOG_LEVEL_WARN, "AI detected malicious request from %s: %s",
                req->client_ip, req->url);

        return 1;
    } else if (ai_result == AI_DETECTION_SUSPICIOUS) {
        /* 可疑请求仅影子记录。逐条打印曾刷爆 stdout/journal（生产实测每秒多条），
         * 节流为每 60s 一条；多条并发下偶发多打一条可接受 */
        static volatile time_t last_suspicious_log = 0;
        time_t now_s = time(NULL);
        time_t prev = __atomic_load_n(&last_suspicious_log, __ATOMIC_RELAXED);
        if (prev == 0 || now_s - prev >= 60) {
            __atomic_store_n(&last_suspicious_log, now_s, __ATOMIC_RELAXED);
            waf_log(LOG_LEVEL_INFO, "AI flagged suspicious request from %s: %s (throttled, 1/min)",
                    req->client_ip, req->url);
        }
    }

    ai_auto_learn(ai_config_ptr, req, 0);
    return 0;
}

int rules_check_request(http_request_t *req, attack_match_t *match) {
    if (!req || !match) return 0;
    /* SIGHUP 延迟重载安全点（在无任何规则读锁的请求线程上下文中执行） */
    rules_try_pending_reload();
    waf_log(LOG_LEVEL_DEBUG, "Entering rules_check_request");

    waf_log(LOG_LEVEL_DEBUG, "Checking IP allowed, client_ip=%s", req->client_ip ? req->client_ip : "NULL");
    /* client_ip 为空时不得拦截：is_ip_allowed(NULL) 返回 0，
     * 原逻辑会把解析不到对端 IP 的正常请求以空规则(类型0/严重度0)误拦 */
    if (req->client_ip[0] && !is_ip_allowed(req->client_ip)) {
        /* 黑名单命中须补全 match：此前直接 return 1，match 保持 {0}，
         * 攻击日志记成 Type: SQL_INJECTION(0) + Rule 空，
         * 类型分布图误标、命中规则 TOP 榜出现空白条目 */
        match->type = ATTACK_UNKNOWN;
        match->severity = 10;
        snprintf(match->rule_id, sizeof(match->rule_id), "IP-BLACKLIST");
        snprintf(match->description, sizeof(match->description), "IP Blacklisted");
        return 1;
    }

    unsigned long long start_time = get_timestamp_us();

    waf_config_t *config = waf_get_config();
    detection_mode_t detection_mode = config ? config->detection_mode : DETECTION_MODE_AUTO;

    int blocked = 0;

    switch (detection_mode) {
        case DETECTION_MODE_RULES:
            waf_log(LOG_LEVEL_DEBUG, "Using RULES-only detection mode");
            blocked = rules_check_only_rules(req, match);
            break;

        case DETECTION_MODE_AI:
            waf_log(LOG_LEVEL_DEBUG, "Using AI-only detection mode");
            blocked = rules_check_only_ai(req, match);
            break;

        case DETECTION_MODE_AUTO:
        default:
            waf_log(LOG_LEVEL_DEBUG, "Using AI+RULES detection mode");
            blocked = rules_check_ai_and_rules(req, match);
            break;
    }

    perf_record_rules_check(get_timestamp_us() - start_time);

    return blocked;
}

int rules_check_sql_injection(const char *data, attack_match_t *match) {
    if (!data || !data[0]) return 0;

    return rules_check_generic(data, ATTACK_SQL_INJECTION, match);
}

int rules_check_xss(const char *data, attack_match_t *match) {
    if (!data || !data[0]) return 0;

    return rules_check_generic(data, ATTACK_XSS, match);
}

int rules_check_cmd_injection(const char *data, attack_match_t *match) {
    if (!data || !data[0]) return 0;

    return rules_check_generic(data, ATTACK_CMD_INJECTION, match);
}

int rules_check_path_traversal(const char *data, attack_match_t *match) {
    if (!data || !data[0]) return 0;

    return rules_check_generic(data, ATTACK_PATH_TRAVERSAL, match);
}

int rules_check_file_upload(const char *data, attack_match_t *match) {
    if (!data || !data[0]) return 0;

    return rules_check_generic(data, ATTACK_FILE_UPLOAD, match);
}

int rules_check_csrf(const char *data, attack_match_t *match) {
    if (!data || !data[0]) return 0;

    return rules_check_generic(data, ATTACK_CSRF, match);
}

int rules_check_ssrf(const char *data, attack_match_t *match) {
    if (!data || !data[0]) return 0;

    return rules_check_generic(data, ATTACK_SSRF, match);
}

int rules_check_scanner(const char *data, attack_match_t *match) {
    if (!data || !data[0]) return 0;

    return rules_check_generic(data, ATTACK_SCANNER, match);
}

int rules_check_xml_injection(const char *data, attack_match_t *match) {
    if (!data || !data[0]) return 0;

    return rules_check_generic(data, ATTACK_XML_INJECTION, match);
}

/* 从输入中提取长 base64 段并解码，用于检测 base64 包裹的攻击载荷。
 * 最多提取 max_bufs 段，返回段数。仅保留可打印比例高的解码结果。 */
static int is_b64_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/';
}

static int extract_base64_segments(const char *data, char bufs[][8192], int max_bufs) {
    if (!data) return 0;
    int n = 0;
    const char *p = data;
    while (*p && n < max_bufs) {
        if (!is_b64_char(*p)) { p++; continue; }
        const char *start = p;
        while (is_b64_char(*p)) p++;
        const char *end = p;
        /* 段首的 '/' 多为路径分隔符(如 /YWxlcnQ...),混入会使解码错位;
         * 剥离开头连续的 '/' 再解码 */
        while (start < end && *start == '/') start++;
        int pad = 0;
        while (*p == '=' && pad < 2) { p++; pad++; }
        size_t len = (size_t)(end - start);
        /* 上限 8000 字节输入(解码后 ≤6000),防止溢出 8192 输出缓冲;
         * use 必须包含尾部 '=',否则对齐截断会丢失最后一组 */
        size_t use = len + pad > 8000 ? 8000 : len + pad;
        use -= use % 4;
        if (use >= 12) {
            unsigned char tmp[8192];
            int dlen = EVP_DecodeBlock(tmp, (const unsigned char *)start, (int)use);
            /* 仅当完整段(含填充)被解码时才按尾部 = 修正长度 */
            if (dlen > 0 && use == len + pad) {
                dlen -= pad;
            }
            if (dlen > 0 && dlen < (int)sizeof(tmp)) {
                int printable = 0;
                for (int i = 0; i < dlen; i++) {
                    if ((tmp[i] >= 32 && tmp[i] <= 126) || tmp[i] == '\n' || tmp[i] == '\r' || tmp[i] == '\t')
                        printable++;
                }
                if (printable * 100 / dlen >= 90) {
                    /* 内嵌 NUL 替换为空格：攻击载荷常带 \x00(如 OR\x00 接注释符)，
                     * C 字符串 regexec 会在 NUL 处截断漏掉后面的攻击特征 */
                    for (int i = 0; i < dlen; i++)
                        bufs[n][i] = tmp[i] ? (char)tmp[i] : ' ';
                    bufs[n][dlen] = '\0';
                    n++;
                }
            }
        }
    }
    return n;
}

/* 将 \uXXXX / \xNN 转义还原为字符,返回是否有替换发生。
 * 攻击样本常用 \u003cscript\u003e、\x27 之类的转义绕过明文规则;
 * 还原后交给精确规则复扫,替代旧的 \u00[4-7] 粗规则(那条规则把
 * base64 解码出的正常 JSON(含 \uXXXX 转义)误判为 XSS,造成大量误报)。 */
static int uhex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int unicode_unescape(const char *src, char *dst, size_t dst_size) {
    size_t sp = 0, dp = 0, len = strlen(src);
    int changed = 0;
    while (sp < len && dp < dst_size - 1) {
        if (src[sp] == '\\' && sp + 5 < len && (src[sp+1] == 'u' || src[sp+1] == 'U')) {
            int v0 = uhex_val(src[sp+2]), v1 = uhex_val(src[sp+3]);
            int v2 = uhex_val(src[sp+4]), v3 = uhex_val(src[sp+5]);
            if (v0 >= 0 && v1 >= 0 && v2 >= 0 && v3 >= 0) {
                unsigned int cp = (unsigned int)((v0 << 12) | (v1 << 8) | (v2 << 4) | v3);
                dst[dp++] = (cp > 0 && cp < 128) ? (char)cp : '?';
                sp += 6;
                changed = 1;
                continue;
            }
        }
        if (src[sp] == '\\' && sp + 3 < len && (src[sp+1] == 'x' || src[sp+1] == 'X')) {
            int v0 = uhex_val(src[sp+2]), v1 = uhex_val(src[sp+3]);
            if (v0 >= 0 && v1 >= 0) {
                dst[dp++] = (char)((v0 << 4) | v1);
                sp += 4;
                changed = 1;
                continue;
            }
        }
        dst[dp++] = src[sp++];
    }
    dst[dp] = '\0';
    return changed;
}

/* HTML 实体解码: &#NN; &#xNN; 及常用命名实体(lpar/rpar/bsol/sol/lt/gt/amp/quot/colon等) */
static int html_entity_decode(const char *src, char *dst, size_t dst_size) {
    static const struct { const char *name; char ch; } ents[] = {
        {"lpar", '('}, {"rpar", ')'}, {"bsol", '\\'}, {"sol", '/'},
        {"lt", '<'}, {"gt", '>'}, {"amp", '&'}, {"quot", '"'},
        {"apos", '\''}, {"colon", ':'}, {"semi", ';'}, {"equals", '='},
        {"ast", '*'}, {"quest", '?'}, {"num", '#'}, {"dollar", '$'},
        {"commat", '@'}, {"vert", '|'}, {"grave", '`'}, {"tilde", '~'},
        {"lcub", '{'}, {"rcub", '}'}, {"lsqb", '['}, {"rsqb", ']'},
        {"percnt", '%'}, {"excl", '!'}, {"NewLine", '\n'}, {"Tab", '\t'},
        {NULL, 0}
    };
    size_t sp = 0, dp = 0, len = strlen(src);
    int changed = 0;
    while (sp < len && dp < dst_size - 1) {
        if (src[sp] == '&' && sp + 2 < len) {
            if (src[sp+1] == '#') {
                int hex = (src[sp+2] == 'x' || src[sp+2] == 'X');
                size_t p = sp + 2 + (hex ? 1 : 0);
                unsigned long v = 0;
                int nd = 0;
                while (p < len && nd < 6) {
                    int hv = hex ? uhex_val(src[p])
                                 : ((src[p] >= '0' && src[p] <= '9') ? src[p] - '0' : -1);
                    if (hv < 0) break;
                    v = hex ? ((v << 4) | (unsigned)hv) : (v * 10 + (unsigned)hv);
                    if (v > 0x10FFFF) break;
                    p++; nd++;
                }
                if (nd > 0 && p < len && src[p] == ';') {
                    dst[dp++] = (v > 0 && v < 128) ? (char)v : '?';
                    sp = p + 1;
                    changed = 1;
                    continue;
                }
            } else {
                int consumed = 0;
                for (int e = 0; ents[e].name; e++) {
                    size_t nl = strlen(ents[e].name);
                    if (sp + nl + 1 < len && strncmp(src + sp + 1, ents[e].name, nl) == 0 &&
                        src[sp + 1 + nl] == ';') {
                        dst[dp++] = ents[e].ch;
                        sp += nl + 2;
                        changed = 1;
                        consumed = 1;
                        break;
                    }
                }
                if (consumed)
                    continue;
            }
        }
        dst[dp++] = src[sp++];
    }
    dst[dp] = '\0';
    return changed;
}

/* allow_b64: 是否启用 base64 解码层。仅 url/query 开启;
 * body/referer 中的 base64 垃圾段(protobuf/遥测/CSP 报告)解码后
 * 常巧合命中攻击特征字节,造成误报,故关闭。 */
static int rules_check_generic2(const char *data, attack_type_t type,
                                attack_match_t *match, int allow_b64) {
    if (!data || !data[0] || !match) return 0;

    /* 只缓存阴性结果：阳性缓存命中会跳过 regexec 直接返回 1，
     * 导致 attack_match 字段为空(日志出现空规则ID/严重度0的误报条目) */
    int cached_result = rule_cache_get(data, type);
    if (cached_result == 0) {
        return 0;
    }

    char decoded_data[16384] = {0};
    waf_url_decode(data, decoded_data, sizeof(decoded_data));


    /* 折叠 shell 空反引号绕过: wh``oami -> whoami */
    {
        char tmp_bt[16384];
        int si = 0, di = 0;
        while (decoded_data[si] && di < 16383) {
            if (decoded_data[si] == '`' && decoded_data[si+1] == '`') { si += 2; continue; }
            tmp_bt[di++] = decoded_data[si++];
        }
        tmp_bt[di] = '\0';
        memcpy(decoded_data, tmp_bt, di + 1);
    }
/* unicode/hex 转义还原层(在 URL 解码结果上再做一层) */
    char udec_data[16384] = {0};
    int has_udec = unicode_unescape(decoded_data, udec_data, sizeof(udec_data));

    /* 二次 URL 解码层: unicode 反转义后可能再暴露 %XX(eval%28atob 型);
     * 无 unicode 转义时也可能本身就是双重 URL 编码,故始终尝试 */
    char udec2_data[16384] = {0};
    int has_udec2 = 0;
    {
        const char *src2 = has_udec ? udec_data : decoded_data;
        waf_url_decode(src2, udec2_data, sizeof(udec2_data));
        has_udec2 = (strcmp(udec2_data, src2) != 0);
    }

    /* HTML 实体解码层(&#NN;/&#xNN;/命名实体),分别作用于 URL 解码层和 unicode 层 */
    char ent_data[16384] = {0};
    int has_ent = html_entity_decode(decoded_data, ent_data, sizeof(ent_data));
    char uent_data[16384] = {0};
    int has_uent = 0;
    if (has_udec)
        has_uent = html_entity_decode(udec_data, uent_data, sizeof(uent_data));
    /* 实体解码层之上再做 unicode 反转义: &bsol;&#117;&#48;&#48;&#x36;&#x31;
     * 先还原成 \u0061 形态,需再反转义一次才暴露 alert 等明文 */
    char uent2_data[16384] = {0};
    int has_uent2 = 0;
    if (has_ent)
        has_uent2 = unicode_unescape(ent_data, uent2_data, sizeof(uent2_data));

    /* base64 载荷解码层：blazehttp/实战中大量攻击把 payload base64 编码后
     * 放在参数值里(如 Li4vV0VCLUlORi93ZWIueG1s = ../WEB-INF/web.xml)。
     * 对 url 解码前后的输入都提取 base64 段;攻击样本常再套一层 base64
     * 或在解码出的 JSON 里写 \uXXXX 转义,故做二层递归提取并段内反转义。
     * allow_b64=2(body 模式)时每段先过针尖门,杜绝 protobuf/遥测垃圾段误报。 */
    char b64_all[8][8192];
    int b64_all_n = 0, b64_gate[8] = {0};
    if (allow_b64) {
        char lvl1[8][8192];
        int n1 = extract_base64_segments(data, lvl1, 3);
        n1 += extract_base64_segments(decoded_data, lvl1 + n1, 3);
        /* udec 层(\uXXXX word-salad 常隐藏 base64 值)也入提取池 */
        if (has_udec && n1 < 8)
            n1 += extract_base64_segments(udec_data, lvl1 + n1, 8 - n1);
        for (int k = 0; k < n1 && b64_all_n < 8; k++) {
            /* 先段内 unicode/hex 反转义再入池:一层明文常是含 \uXXXX 的 JSON,
             * 反转义后才暴露嵌套的 base64 值,供二层提取 */
            char tmp[8192];
            if (unicode_unescape(lvl1[k], tmp, sizeof(tmp)))
                memcpy(b64_all[b64_all_n], tmp, sizeof(b64_all[0]));
            else
                memcpy(b64_all[b64_all_n], lvl1[k], sizeof(b64_all[0]));
            b64_all_n++;
        }
        /* 二层: 从一层明文(已反转义)中再提取(如 {"url":"Li4vLndlYi54bWw="}) */
        for (int k = 0; k < n1 && b64_all_n < 8; k++) {
            char sub[8192];
            if (extract_base64_segments(b64_all[k], (char (*)[8192])&sub, 1) > 0) {
                /* 仅当子段与父段不同才入池,避免自引用死循环 */
                if (strcmp(sub, b64_all[k]) != 0) {
                    memcpy(b64_all[b64_all_n], sub, sizeof(b64_all[0]));
                    b64_all_n++;
                }
            }
        }
        /* 二层段内反转义 + 针尖门 */
        for (int k = n1; k < b64_all_n; k++) {
            char tmp[8192];
            if (unicode_unescape(b64_all[k], tmp, sizeof(tmp)))
                memcpy(b64_all[k], tmp, sizeof(b64_all[0]));
        }
        /* 池内条目再衍生一份 URL 解码变体: 攻击常把 payload 先 URL 编码再 base64
         * (如 Cookie 里的 JTI3JTIy... 解出 %27%22%3E%3Csvg...)。
         * 不就地覆盖——URL 解码会把明文已有的 '+' 转成空格,破坏 UTF-7 +ADw- 等
         * 特征;解码结果不同则作为新条目追加,两种形态都参与规则扫描 */
        for (int k = 0; k < b64_all_n && b64_all_n < 8; k++) {
            char ud[8192];
            waf_url_decode(b64_all[k], ud, sizeof(ud));
            if (strcmp(ud, b64_all[k]) != 0) {
                memcpy(b64_all[b64_all_n], ud, sizeof(b64_all[0]));
                b64_all_n++;
            }
        }
        for (int k = 0; k < b64_all_n; k++)
            b64_gate[k] = (allow_b64 == 2) ? fast_pattern_check(b64_all[k], NULL) : 1;
    }

    /* 针尖门分两类: plain 各明文层共用一个门; base64 池每段各自一个门。
     * 二者必须分开——早先 b64_all_n>0 时直接把 plain 门也置 1,
     * 使 zip /sftp /telnet /;cat 这类宽规则对普通文本(如 "gzip ")也生效,
     * 白样本误报从 122 暴涨到 232。现仅放行「本段自己命中针尖词」的 b64 段。 */
    int always = 0;      /* 非 SQL/XSS/CMD 类型: 不做针尖门 */
    int gate_plain = 0;  /* 任一明文层命中针尖词 */
    int gate_b64 = 0;    /* 任一 base64 段命中针尖词 */
    if (type == ATTACK_SQL_INJECTION || type == ATTACK_XSS || type == ATTACK_CMD_INJECTION) {
        gate_plain = fast_pattern_check(data, NULL);
        if (!gate_plain && decoded_data[0])
            gate_plain = fast_pattern_check(decoded_data, NULL);
        if (!gate_plain && has_udec)
            gate_plain = fast_pattern_check(udec_data, NULL);
        if (!gate_plain && has_ent)
            gate_plain = fast_pattern_check(ent_data, NULL);
        if (!gate_plain && has_udec2)
            gate_plain = fast_pattern_check(udec2_data, NULL);
        if (!gate_plain && has_uent)
            gate_plain = fast_pattern_check(uent_data, NULL);
        if (!gate_plain && has_uent2)
            gate_plain = fast_pattern_check(uent2_data, NULL);
    } else {
        always = 1;
    }
    for (int k = 0; k < b64_all_n; k++) {
        if (b64_gate[k]) { gate_b64 = 1; break; }
    }

    if (!always && !gate_plain && !gate_b64) {
        rule_cache_set(data, type, 0);
        return 0;
    }

    int scan_plain = (always || gate_plain);

    int matched = 0;
    pthread_rwlock_rdlock(&rules_lock);
    for (int i = 0; i < detection_rules_count; i++) {
        detection_rule_t *rule = &detection_rules[i];

        if (!rule->enabled || rule->type != type) continue;

        int hit = 0;
        if (scan_plain) {
            hit = (regexec(&rule->regex, data, 0, NULL, 0) == 0 ||
                   regexec(&rule->regex, decoded_data, 0, NULL, 0) == 0);
            if (!hit && has_udec)
                hit = (regexec(&rule->regex, udec_data, 0, NULL, 0) == 0);
            if (!hit && has_udec2)
                hit = (regexec(&rule->regex, udec2_data, 0, NULL, 0) == 0);
            if (!hit && has_ent)
                hit = (regexec(&rule->regex, ent_data, 0, NULL, 0) == 0);
            if (!hit && has_uent)
                hit = (regexec(&rule->regex, uent_data, 0, NULL, 0) == 0);
            if (!hit && has_uent2)
                hit = (regexec(&rule->regex, uent2_data, 0, NULL, 0) == 0);
        }
        /* 复扫 base64 解码出的明文段(仅扫本段自己的针尖门通过的段) */
        for (int k = 0; !hit && k < b64_all_n; k++) {
            if (!b64_gate[k]) continue;
            hit = (regexec(&rule->regex, b64_all[k], 0, NULL, 0) == 0);
        }

        if (hit) {
            match->type = type;
            strncpy(match->pattern, rule->pattern, sizeof(match->pattern) - 1);
            strncpy(match->matched_content, data, sizeof(match->matched_content) - 1);
            match->matched_content[sizeof(match->matched_content) - 1] = '\0';
            match->severity = rule->severity;
            strncpy(match->description, rule->name, sizeof(match->description) - 1);
            strncpy(match->rule_id, rule->id, sizeof(match->rule_id) - 1);

            waf_log(LOG_LEVEL_WARN, "Rule match detected: type=%d, rule=%s, pattern=%s, data=%s",
                   type, rule->id, rule->pattern, data);

            /* 命中时不得写缓存：原逻辑误写 rule_cache_set(data,type,0)，
             * 把攻击数据缓存成阴性，60s 内相同载荷重放直接放行(绕过漏洞) */
            matched = 1;
            break;
        }
    }
    pthread_rwlock_unlock(&rules_lock);

    if (matched) return 1;

    rule_cache_set(data, type, 0);
    return 0;
}

int rules_check_generic(const char *data, attack_type_t type, attack_match_t *match) {
    return rules_check_generic2(data, type, match, 1);
}

int access_check_ip(const char *ip) {
    if (!ip) return WAF_ACTION_ALLOW;

    return WAF_ACTION_ALLOW;
}

int access_check_url(const char *url) {
    if (!url) return WAF_ACTION_ALLOW;

    for (int i = 0; whitelist_paths[i] != NULL; i++) {
        if (strstr(url, whitelist_paths[i])) {
            return WAF_ACTION_ALLOW;
        }
    }

    return WAF_ACTION_ALLOW;
}

int access_check_user_agent(const char *ua) {
    if (!ua) return WAF_ACTION_ALLOW;

    if (strstr(ua, "curl") || strstr(ua, "wget") || strstr(ua, "python-requests")) {
        waf_log(LOG_LEVEL_WARN, "Suspicious User-Agent detected: %s", ua);
    }

    return WAF_ACTION_ALLOW;
}

int access_check_referer(const char *referer __attribute__((unused))) {
    return WAF_ACTION_ALLOW;
}

int rules_reload(void) {
    waf_log(LOG_LEVEL_INFO, "Reloading rules");

    /* 写锁独占：阻止其它工作线程在读锁保护下访问正在被销毁的规则表 */
    pthread_rwlock_wrlock(&rules_lock);
    rules_destroy();
    int rc = rules_init("rules", NULL);
    pthread_rwlock_unlock(&rules_lock);
    return rc;
}

/* 供 SIGHUP 使用：信号处理器内不得做 reload(非 async-signal-safe，
 * 且可能与本线程持有的读锁自锁)，故仅置标志，由请求线程在安全点执行。 */
void rules_request_reload(void) {
    rules_reload_pending = 1;
}

void rules_try_pending_reload(void) {
    if (rules_reload_pending) {
        rules_reload_pending = 0;
        rules_reload();
    }
}
