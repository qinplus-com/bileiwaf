#define _GNU_SOURCE
#include "../include/waf_blockpage.h"
#include "../include/waf_common.h"
#include "../include/waf_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#define BP_TPL_MAX  32768   /* 模板上限（须小于 http_set_body 的 MAX_BODY_SIZE） */
#define BP_AD_MAX   8192    /* 广告片段上限 */
#define BP_PATH_MAX 512

typedef struct {
    int  enabled;                       /* 0 => 不接管，沿用内置极简 403 */
    int  ad_enabled;                    /* 1 => 注入广告位 */
    char ad_mode[16];                   /* none | banner | iframe | script */
    char ad_image[BP_PATH_MAX];
    char ad_link[BP_PATH_MAX];
    char ad_alt[128];
    char ad_iframe[BP_PATH_MAX];
    char ad_script_file[BP_PATH_MAX];   /* 第三方广告 JS 片段文件 */
    char template_path[BP_PATH_MAX];    /* 自定义模板文件，空则用内置模板 */
} bp_conf_t;

static bp_conf_t   g_conf;
static char        g_tpl[BP_TPL_MAX];
static size_t      g_tpl_len;
static char        g_ad[BP_AD_MAX];
static size_t      g_ad_len;
static int         g_ready;
static pthread_mutex_t g_bp_lock = PTHREAD_MUTEX_INITIALIZER;

/* 内置模板：深色卡片风格，与产品视觉一致；{{ad}} 位置由广告片段替换 */
static const char *BP_DEFAULT_TPL =
"<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"UTF-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
"<meta name=\"robots\" content=\"noindex,nofollow\">\n"
"<title>403 访问已被拦截 · 壁垒WAF</title>\n<style>\n"
"*{box-sizing:border-box}\n"
"body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;"
"background:#0b1220;color:#d8e4f5;font:14px/1.7 -apple-system,BlinkMacSystemFont,"
"'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif}\n"
".card{width:min(560px,92vw);padding:34px 32px;border:1px solid #1c2f4d;border-radius:14px;"
"background:linear-gradient(160deg,#12233f,#0d1a2e)}\n"
".brand{color:#22d3ee;font-weight:700;letter-spacing:2px;font-size:13px}\n"
"h1{margin:10px 0 6px;font-size:20px;font-weight:700}\n"
".tip{margin:0;font-size:12px;color:#6f8299}\n"
".meta{margin:16px 0 0;padding:12px 14px;background:#0f1e35;border-radius:8px;"
"font-size:12px;color:#8fa6c2;word-break:break-all}\n"
".meta b{color:#c7d7ea;font-weight:600}\n"
".ad{margin-top:20px;text-align:center}\n"
".ad img{max-width:100%;border:0;border-radius:8px}\n"
".ad iframe{width:100%;border:0}\n"
".ad .tag{margin-top:6px;font-size:11px;color:#5b6d85}\n"
"</style>\n</head>\n<body>\n<div class=\"card\">\n"
"<div class=\"brand\">壁垒WAF</div>\n"
"<h1>访问已被安全策略拦截</h1>\n"
"<p class=\"tip\">您的请求触发了安全防护规则，本次访问已被阻止。</p>\n"
"<div class=\"meta\">来源 IP：<b>{{ip}}</b><br>命中规则：<b>{{rule}}</b><br>"
"时间：<b>{{time}}</b></div>\n"
"{{ad}}\n</div>\n</body>\n</html>";

static const char *bp_home(void) {
    const char *h = getenv("WAF_HOME");
    if (h && h[0]) return h;
#ifdef WAF_PREFIX
    return WAF_PREFIX;
#else
    return "/opt/bileiwaf";
#endif
}

/* 配置值中的路径：绝对路径直接用，相对路径基于 WAF_HOME */
static void bp_abs_path(const char *val, char *out, size_t outsz) {
    if (!val || !val[0]) { out[0] = '\0'; return; }
    if (val[0] == '/') snprintf(out, outsz, "%s", val);
    else snprintf(out, outsz, "%s/%s", bp_home(), val);
}

/* 读取整个文件到缓冲区；返回字节数，失败返回 -1 */
static long bp_read_file(const char *path, char *buf, size_t bufsz) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    size_t n = fread(buf, 1, bufsz - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    return (long)n;
}

/* HTML 转义：拦截页里的 IP / 规则名 / URL 都可能来自攻击者 */
static void bp_escape(const char *src, char *out, size_t outsz) {
    size_t o = 0;
    if (!src) src = "";
    for (const char *p = src; *p && o + 8 < outsz; p++) {
        switch (*p) {
        case '&':  memcpy(out + o, "&amp;", 5);  o += 5; break;
        case '<':  memcpy(out + o, "&lt;", 4);   o += 4; break;
        case '>':  memcpy(out + o, "&gt;", 4);   o += 4; break;
        case '"':  memcpy(out + o, "&quot;", 6); o += 6; break;
        case '\'': memcpy(out + o, "&#39;", 5);  o += 5; break;
        default:   out[o++] = *p; break;
        }
    }
    out[o] = '\0';
}

/* 广告链接只接受 http/https，避免 javascript:/data: 造成的点击型 XSS */
static int bp_url_ok(const char *u) {
    return u && (strncmp(u, "http://", 7) == 0 || strncmp(u, "https://", 8) == 0);
}

static void bp_trim(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n'))
        s[--n] = '\0';
}

static int bp_load_conf(void) {
    memset(&g_conf, 0, sizeof(g_conf));
    g_conf.enabled = 0;
    g_conf.ad_enabled = 0;
    snprintf(g_conf.ad_mode, sizeof(g_conf.ad_mode), "none");

    char path[1024];
    snprintf(path, sizeof(path), "%s/config/blockpage.conf", bp_home());
    FILE *fp = fopen(path, "r");
    if (!fp) {
        waf_log(LOG_LEVEL_INFO, "Block page config not found (%s), using built-in minimal 403", path);
        return -1;
    }

    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        char *s = line;
        bp_trim(s);
        if (s[0] == '#' || s[0] == '\0') continue;
        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char key[128], val[1400];
        snprintf(key, sizeof(key), "%s", s);
        snprintf(val, sizeof(val), "%s", eq + 1);
        bp_trim(key); bp_trim(val);

        if      (!strcmp(key, "enabled"))        g_conf.enabled = atoi(val);
        else if (!strcmp(key, "ad_enabled"))     g_conf.ad_enabled = atoi(val);
        else if (!strcmp(key, "ad_mode"))        snprintf(g_conf.ad_mode, sizeof(g_conf.ad_mode), "%s", val);
        else if (!strcmp(key, "ad_image"))       snprintf(g_conf.ad_image, sizeof(g_conf.ad_image), "%s", val);
        else if (!strcmp(key, "ad_link"))        snprintf(g_conf.ad_link, sizeof(g_conf.ad_link), "%s", val);
        else if (!strcmp(key, "ad_alt"))         snprintf(g_conf.ad_alt, sizeof(g_conf.ad_alt), "%s", val);
        else if (!strcmp(key, "ad_iframe"))      snprintf(g_conf.ad_iframe, sizeof(g_conf.ad_iframe), "%s", val);
        else if (!strcmp(key, "ad_script_file")) snprintf(g_conf.ad_script_file, sizeof(g_conf.ad_script_file), "%s", val);
        else if (!strcmp(key, "template"))       snprintf(g_conf.template_path, sizeof(g_conf.template_path), "%s", val);
    }
    fclose(fp);
    return 0;
}

/* 生成广告片段 HTML */
static void bp_build_ad(void) {
    g_ad[0] = '\0'; g_ad_len = 0;
    if (!g_conf.ad_enabled || !strcmp(g_conf.ad_mode, "none")) return;

    char esc_link[1400] = "", esc_img[1400] = "", esc_alt[300] = "", esc_iframe[1400] = "";

    if (!strcmp(g_conf.ad_mode, "banner")) {
        if (!bp_url_ok(g_conf.ad_image)) {
            waf_log(LOG_LEVEL_WARN, "Block page ad_image ignored (only http/https URL): %s", g_conf.ad_image);
            return;
        }
        if (!bp_url_ok(g_conf.ad_link)) {
            waf_log(LOG_LEVEL_WARN, "Block page ad_link ignored (only http/https allowed): %s", g_conf.ad_link);
            return;
        }
        bp_escape(g_conf.ad_link, esc_link, sizeof(esc_link));
        bp_escape(g_conf.ad_image, esc_img, sizeof(esc_img));
        bp_escape(g_conf.ad_alt, esc_alt, sizeof(esc_alt));
        g_ad_len = snprintf(g_ad, sizeof(g_ad),
            "<div class=\"ad\"><a href=\"%s\" target=\"_blank\" rel=\"noopener sponsored\">"
            "<img src=\"%s\" alt=\"%s\"></a><div class=\"tag\">广告</div></div>",
            esc_link, esc_img, esc_alt[0] ? esc_alt : "广告");
    } else if (!strcmp(g_conf.ad_mode, "iframe")) {
        if (!bp_url_ok(g_conf.ad_iframe)) {
            waf_log(LOG_LEVEL_WARN, "Block page ad_iframe ignored (only http/https allowed): %s", g_conf.ad_iframe);
            return;
        }
        bp_escape(g_conf.ad_iframe, esc_iframe, sizeof(esc_iframe));
        g_ad_len = snprintf(g_ad, sizeof(g_ad),
            "<div class=\"ad\"><iframe src=\"%s\" height=\"90\" scrolling=\"no\" "
            "sandbox=\"allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox\">"
            "</iframe><div class=\"tag\">广告</div></div>", esc_iframe);
    } else if (!strcmp(g_conf.ad_mode, "script")) {
        char path[1024];
        bp_abs_path(g_conf.ad_script_file, path, sizeof(path));
        long n = path[0] ? bp_read_file(path, g_ad, sizeof(g_ad)) : -1;
        if (n <= 0) {
            waf_log(LOG_LEVEL_WARN, "Block page ad script not readable: %s", path[0] ? path : "(未配置 ad_script_file)");
            return;
        }
        g_ad_len = (size_t)n;
    }
}

static int bp_apply(void) {
    /* 先读配置，再按配置加载模板与广告 */
    bp_load_conf();

    if (!g_conf.enabled) {
        g_tpl_len = 0; g_ad_len = 0;
        waf_log(LOG_LEVEL_INFO, "Block page disabled (built-in minimal 403 in use)");
        return 0;
    }

    if (g_conf.template_path[0]) {
        char path[1024];
        bp_abs_path(g_conf.template_path, path, sizeof(path));
        long n = bp_read_file(path, g_tpl, sizeof(g_tpl));
        if (n > 0) {
            g_tpl_len = (size_t)n;
        } else {
            waf_log(LOG_LEVEL_WARN, "Block page template unreadable (%s), fallback to built-in", path);
            snprintf(g_tpl, sizeof(g_tpl), "%s", BP_DEFAULT_TPL);
            g_tpl_len = strlen(g_tpl);
        }
    } else {
        snprintf(g_tpl, sizeof(g_tpl), "%s", BP_DEFAULT_TPL);
        g_tpl_len = strlen(g_tpl);
    }

    bp_build_ad();

    waf_log(LOG_LEVEL_INFO, "Block page ready: template=%zu bytes, ad=%s(%zu bytes)",
            g_tpl_len, g_conf.ad_enabled ? g_conf.ad_mode : "off", g_ad_len);
    return 1;
}

int blockpage_reload(void) {
    pthread_mutex_lock(&g_bp_lock);
    int ok = bp_apply();
    g_ready = 1;
    pthread_mutex_unlock(&g_bp_lock);
    return ok;
}

int blockpage_init(void) {
    return blockpage_reload();
}

/* 单遍展开模板占位符，避免逐个 strstr 替换带来的二次扫描与长度错乱 */
size_t blockpage_render(char *out, size_t outsz,
                        const char *ip, const char *rule, const char *url) {
    if (!out || outsz == 0) return 0;

    char esc_ip[256], esc_rule[512], esc_url[4096], tstr[64];
    bp_escape(ip, esc_ip, sizeof(esc_ip));
    bp_escape(rule, esc_rule, sizeof(esc_rule));
    bp_escape(url, esc_url, sizeof(esc_url));
    time_t now = time(NULL);
    strftime(tstr, sizeof(tstr), "%Y-%m-%d %H:%M:%S", localtime(&now));

    pthread_mutex_lock(&g_bp_lock);
    if (!g_ready || !g_conf.enabled || g_tpl_len == 0) {
        pthread_mutex_unlock(&g_bp_lock);
        return 0;
    }

    size_t o = 0;
    for (size_t i = 0; i < g_tpl_len; ) {
        if (g_tpl[i] == '{' && i + 1 < g_tpl_len && g_tpl[i + 1] == '{') {
            size_t j = i + 2;
            while (j + 1 < g_tpl_len && !(g_tpl[j] == '}' && g_tpl[j + 1] == '}')) j++;
            if (j + 1 < g_tpl_len) {
                size_t klen = j - (i + 2);
                const char *rep = NULL;
                size_t rep_len = 0;
                if      (klen == 2 && !strncmp(g_tpl + i + 2, "ip",   2)) { rep = esc_ip;   rep_len = strlen(esc_ip); }
                else if (klen == 4 && !strncmp(g_tpl + i + 2, "rule", 4)) { rep = esc_rule; rep_len = strlen(esc_rule); }
                else if (klen == 3 && !strncmp(g_tpl + i + 2, "url",  3)) { rep = esc_url;  rep_len = strlen(esc_url); }
                else if (klen == 4 && !strncmp(g_tpl + i + 2, "time", 4)) { rep = tstr;     rep_len = strlen(tstr); }
                else if (klen == 2 && !strncmp(g_tpl + i + 2, "ad",   2)) { rep = g_ad;     rep_len = g_ad_len; }

                if (rep) {
                    if (o + rep_len >= outsz) { pthread_mutex_unlock(&g_bp_lock); return 0; }
                    memcpy(out + o, rep, rep_len);
                    o += rep_len;
                    i = j + 2;
                    continue;
                }
            }
        }
        if (o + 1 >= outsz) { pthread_mutex_unlock(&g_bp_lock); return 0; }
        out[o++] = g_tpl[i++];
    }
    pthread_mutex_unlock(&g_bp_lock);

    out[o] = '\0';
    return o;
}
