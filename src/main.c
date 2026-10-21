#include "../include/waf.h"
#include "../include/version.h"
#include "../include/waf_ssl.h"
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#if defined(USE_OPENSSL)
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#endif

#define PID_FILE "/tmp/waf.pid"
#define BACKEND_PID_DIR "/tmp/waf-backend-pids"
#define BACKEND_LOG_DIR "/tmp/waf-backend-logs"
#define BACKEND_BINARY "/opt/waf/simple_backend"
#define CERT_DIR "/etc/letsencrypt/live"
#define WAF_CONFIG_DIR "/opt/waf/config"
#define WAF_DEFAULT_CERT_DIR "certs"

void print_usage(const char *prog) {
    printf("Usage: %s <command> [options]\n", prog);
    printf("\nCommands:\n");
    printf("  start           Start WAF service\n");
    printf("  stop            Stop WAF service\n");
    printf("  status          Show WAF status\n");
    printf("  restart         Restart WAF service\n");
    printf("  sites           Show configured sites\n");
    printf("  check, -t       Validate configuration (like nginx -t)\n");
    printf("  backend         Manage backend services\n");
    printf("  cert            Manage SSL certificates\n");
    printf("  webadmin        WAF management interface (HTTP/HTTPS)\n");
    printf("  bypass          Bypass module for special sites\n");
    printf("  help            Show this help message\n");
    printf("\nBackend subcommands:\n");
    printf("  backend start <site>      Start backend for specified site\n");
    printf("  backend stop <site>       Stop backend for specified site\n");
    printf("  backend status <site>     Show status of backend for specified site\n");
    printf("  backend start-all         Start backends for all sites\n");
    printf("  backend stop-all          Stop backends for all sites\n");
    printf("  backend status-all        Show status of all backends\n");
    printf("\nCertificate subcommands:\n");
    printf("  cert status               Show certificate status\n");
    printf("  cert set <cert> <key>     Set SSL certificate and key paths\n");
    printf("  cert generate             Generate self-signed certificate\n");
    printf("  cert issue <domain>       Issue Let's Encrypt certificate\n");
    printf("  cert renew                Renew Let's Encrypt certificates\n");
    printf("  cert list                 List all installed certificates\n");
    printf("\nWebAdmin subcommands:\n");
    printf("  webadmin start            Start WebAdmin server (HTTP:8080, HTTPS:28443)\n");
    printf("  webadmin stop             Stop WebAdmin server\n");
    printf("  webadmin restart          Restart WebAdmin server\n");
    printf("  webadmin status           Show WebAdmin server status\n");
    printf("\nOptions (for start command):\n");
    printf("  -p <port>        HTTP port (default: %d)\n", WAF_DEFAULT_HTTP_PORT);
    printf("  -s <port>        HTTPS port (default: %d)\n", WAF_DEFAULT_HTTPS_PORT);
    printf("  -b <host:port>   Backend server (default: %s:%d)\n",
           WAF_DEFAULT_BACKEND_HOST, WAF_DEFAULT_BACKEND_PORT);
    printf("  -m <mode>        Protection mode: learning|detection|blocking (default: blocking)\n");
    printf("  -w <threads>     Number of worker threads (default: %d)\n", WAF_WORKER_THREADS);
    printf("  -c <config>      Configuration file\n");
    printf("  -l <dir>         Log directory (default: logs)\n");
    printf("  -r <dir>         Rules directory (default: rules)\n");
    printf("  --no-cc          Disable CC protection\n");
    printf("  --no-api         Disable API protection\n");
    printf("  --daemon         Run in background\n");
    printf("\nExamples:\n");
    printf("  %s start -p 80 -m detection\n", prog);
    printf("  %s start --daemon\n", prog);
    printf("  %s stop\n", prog);
    printf("  %s status\n", prog);
    printf("  %s sites\n", prog);
    printf("  %s backend start examples.com\n", prog);
    printf("  %s cert issue examples.com\n", prog);
    printf("  %s cert set /path/to/cert.pem /path/to/key.pem\n", prog);
    printf("  %s webadmin start\n", prog);
    printf("\n");
}

void print_version(void) {
    printf("WAF (Web Application Firewall) v%s\n", WAF_VERSION);
    printf("Built for Linux\n");
    printf("Developer: qinplus.com\n");
    printf("\n");
}

const char *waf_pid_file(void) {
    const char *env = getenv("WAF_PID_FILE");
    return (env && env[0]) ? env : PID_FILE;
}

int read_pid_file(pid_t *pid) {
    FILE *fp = fopen(waf_pid_file(), "r");
    if (!fp) return -1;

    if (fscanf(fp, "%d", pid) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

int write_pid_file(pid_t pid) {
    FILE *fp = fopen(waf_pid_file(), "w");
    if (!fp) return -1;
    
    fprintf(fp, "%d\n", pid);
    fclose(fp);
    return 0;
}

int stop_waf(void) {
    pid_t pid;
    if (read_pid_file(&pid) != 0) {
        printf("WAF is not running\n");
        return 0;
    }
    
    if (kill(pid, SIGTERM) != 0) {
        perror("Failed to stop WAF");
        return -1;
    }
    
    sleep(1);
    
    if (kill(pid, 0) == 0) {
        kill(pid, SIGKILL);
        sleep(1);
    }
    
    unlink(PID_FILE);
    printf("WAF stopped\n");
    return 0;
}

int is_process_running(pid_t pid) {
    if (pid <= 0) return 0;
    
    if (kill(pid, 0) == 0) {
        return 1;
    }
    
    if (errno == EPERM) {
        return 1;
    }
    
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/status", pid);
    
    FILE *fp = fopen(proc_path, "r");
    if (!fp) {
        return 0;
    }
    
    char comm[256] = {0};
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Name:", 5) == 0) {
            sscanf(line + 5, "%255s", comm);
            break;
        }
    }
    fclose(fp);
    
    if (strcmp(comm, "waf") == 0 || strstr(comm, "waf") != NULL) {
        return 1;
    }
    
    return 0;
}

static void get_process_stats(pid_t pid, long *cpu_usage, long *mem_kb, time_t *start_time) {
    char stat_path[64];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    
    FILE *fp = fopen(stat_path, "r");
    if (!fp) return;
    
    char line[2048];
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return;
    }
    fclose(fp);
    
    char *p = line;
    char *end;
    
    p = strchr(p, ')');
    if (!p) return;
    p += 2;
    
    for (int i = 0; i < 11; i++) {
        p = strchr(p, ' ');
        if (!p) return;
        p++;
    }
    
    unsigned long long utime = strtoull(p, &end, 10);
    p = end + 1;
    
    unsigned long long stime = strtoull(p, &end, 10);
    p = end + 1;
    
    for (int i = 0; i < 6; i++) {
        p = strchr(p, ' ');
        if (!p) return;
        p++;
    }
    
    unsigned long long starttime = strtoull(p, &end, 10);
    p = end + 1;
    
    for (int i = 0; i < 1; i++) {
        p = strchr(p, ' ');
        if (!p) return;
        p++;
    }
    
    unsigned long rss = strtoul(p, &end, 10);
    
    if (cpu_usage) *cpu_usage = utime + stime;
    if (mem_kb) *mem_kb = rss * 4;
    if (start_time) {
        long clk_tck = sysconf(_SC_CLK_TCK);
        *start_time = time(NULL) - (starttime / clk_tck);
    }
}

int status_waf(void) {
    pid_t pid;
    if (read_pid_file(&pid) != 0) {
        printf("  ____  _ _ _       \n");
        printf(" | __ )(_) | |___   \n");
        printf(" |  _ \\| | | / __|  \n");
        printf(" | |_) | | | \\__ \\  \n");
        printf(" |____/|_|_|_|___/  \n");
        printf("                    \n");
        printf(" Status: STOPPED\n");
        return 0;
    }
    
    if (!is_process_running(pid)) {
        unlink(PID_FILE);
        printf("  ____  _ _ _       \n");
        printf(" | __ )(_) | |___   \n");
        printf(" |  _ \\| | | / __|  \n");
        printf(" | |_) | | | \\__ \\  \n");
        printf(" |____/|_|_|_|___/  \n");
        printf("                    \n");
        printf(" Status: STOPPED (stale pid file)\n");
        return 0;
    }
    
    long cpu_usage = 0, mem_kb = 0;
    time_t start_time = 0;
    get_process_stats(pid, &cpu_usage, &mem_kb, &start_time);
    
    time_t now = time(NULL);
    long uptime = now - start_time;
    int days = uptime / 86400;
    int hours = (uptime % 86400) / 3600;
    int minutes = (uptime % 3600) / 60;
    int seconds = uptime % 60;
    
    waf_config_t config = {0};
    config.http_port = WAF_DEFAULT_HTTP_PORT;
    config.https_port = WAF_DEFAULT_HTTPS_PORT;
    config.backend_port = WAF_DEFAULT_BACKEND_PORT;
    strcpy(config.backend_host, WAF_DEFAULT_BACKEND_HOST);
    strcpy(config.log_dir, "logs");
    strcpy(config.rules_dir, "rules");
    
    waf_sites_init(&config);

    /* 与数据平面 init 相同的查找顺序：CWD → $WAF_HOME → 安装前缀 → /opt/waf */
    static char home_sites_path[512];
    const char *site_config_paths[] = {
        "config/sites.conf",
        home_sites_path,
        WAF_PREFIX "/config/sites.conf",
        "/opt/waf/config/sites.conf"
    };
    {
        const char *home = getenv("WAF_HOME");
        if (home && home[0])
            snprintf(home_sites_path, sizeof(home_sites_path), "%s/config/sites.conf", home);
        else
            home_sites_path[0] = '\0';
    }
    
    for (int i = 0; i < (int)(sizeof(site_config_paths)/sizeof(site_config_paths[0])); i++) {
        if (waf_load_sites_from_file(&config, site_config_paths[i]) == 0) {
            break;
        }
    }
    
    if (config.site_count == 0) {
        waf_add_site(&config, "demo.local", "web", "127.0.0.1", 9000);
    }
    
    printf("   ___  ______   ________  _      _____   ____ \n");
    printf("  / _ )/  _/ /  / __/  _/ | | /| / / _ | / __/ \n");
    printf(" / _  |/ // /__/ _/_/ /   | |/ |/ / __ |/ _/  \n");
    printf("/____/___/____/___/___/   |__/|__/_/ |_/_/    \n");
    printf("\n");
    
    printf(" Status:     [ RUNNING ]\n");
    printf(" PID:        %d\n", pid);
    printf(" Uptime:     %d days %02d:%02d:%02d\n", days, hours, minutes, seconds);
    printf(" CPU Time:   %lu ms\n", cpu_usage * 10);
    printf(" Memory:     %ld KB (%.1f MB)\n", mem_kb, mem_kb / 1024.0);
    printf("\n");
    
    printf(" Network Configuration:\n");
    printf(" ---------------------\n");
    printf("   HTTP:       Port %d\n", config.http_port);
    
    char ssl_status[16];
    if (access("certs/dbask.cn.crt", F_OK) == 0 && access("certs/dbask.cn.key", F_OK) == 0) {
        strcpy(ssl_status, "[✓ Ready]");
    } else {
        strcpy(ssl_status, "[✗ Missing]");
    }
    printf("   HTTPS:      Port %d %s\n", config.https_port, ssl_status);
    printf("   Threads:    %d\n", config.worker_threads > 0 ? config.worker_threads : 4);
    printf("   Backend:    %s:%d\n", config.backend_host, config.backend_port);
    printf("\n");
    
    printf(" Module Status:\n");
    printf(" -------------\n");
    
    FILE *fp = fopen("rules/waf_rules.json", "r");
    if (fp) {
        fclose(fp);
        printf("   [✓] Rules Engine      Loaded\n");
    } else {
        fp = fopen("rules/rules.json", "r");
        if (fp) {
            fclose(fp);
            printf("   [✓] Rules Engine      Loaded\n");
        } else {
            printf("   [~] Rules Engine      Default rules\n");
        }
    }
    
    fp = fopen("models/ai_model.dat", "r");
    if (fp) {
        fclose(fp);
        printf("   [✓] AI Defense        Loaded\n");
    } else {
        printf("   [~] AI Defense        Default\n");
    }
    
    printf("   [✓] CC Protection     Enabled\n");
    printf("   [✓] WebSocket         Enabled\n");
    printf("   [✓] FastCGI           Enabled\n");
    printf("   [✓] Proxy             Enabled\n");
    printf("   [✓] Logging           Enabled\n");
    
    if (access("certs/dbask.cn.crt", F_OK) == 0 && access("certs/dbask.cn.key", F_OK) == 0) {
        printf("   [✓] SSL/TLS           Ready\n");
    } else {
        printf("   [~] SSL/TLS           Not configured\n");
    }
    printf("\n");
    
    printf(" Sites (%d):\n", config.site_count);
    printf(" ----------\n");
    
    for (int i = 0; i < config.site_count && i < 5; i++) {
        waf_site_config_t *site = &config.sites[i];
        printf("     %s -> %s:%d", site->domains[0] ? site->domains[0] : "unknown", 
               site->backend_host, site->backend_port);
        if (site->cert_file[0]) {
            printf(" [SSL]");
        }
        printf("\n");
    }
    
    if (config.site_count > 5) {
        printf("     ... and %d more sites\n", config.site_count - 5);
    }
    printf("\n");
    
    printf(" Log Files:\n");
    printf(" ---------\n");
    
    FILE *log_fp = fopen("logs/waf-access.log", "r");
    if (log_fp) {
        fseek(log_fp, 0, SEEK_END);
        long size = ftell(log_fp);
        fclose(log_fp);
        printf("   Access:    %ld bytes\n", size);
    }
    
    log_fp = fopen("logs/waf-attack.log", "r");
    if (log_fp) {
        fseek(log_fp, 0, SEEK_END);
        long size = ftell(log_fp);
        fclose(log_fp);
        printf("   Attack:    %ld bytes\n", size);
    }
    
    log_fp = fopen("logs/waf-error.log", "r");
    if (log_fp) {
        fseek(log_fp, 0, SEEK_END);
        long size = ftell(log_fp);
        fclose(log_fp);
        printf("   Error:     %ld bytes\n", size);
    }
    
    printf("\n");
    printf(" Key: [✓] Active  [✗] Inactive  [~] Default\n");
    printf("\n");
    
    return 0;
}

int show_sites(void) {
    waf_config_t config = {0};
    config.http_port = WAF_DEFAULT_HTTP_PORT;
    config.https_port = WAF_DEFAULT_HTTPS_PORT;
    config.backend_port = WAF_DEFAULT_BACKEND_PORT;
    strcpy(config.backend_host, WAF_DEFAULT_BACKEND_HOST);
    strcpy(config.log_dir, "logs");
    strcpy(config.rules_dir, "rules");
    
    waf_sites_init(&config);
    
    const char *site_config_paths[] = {
        WAF_CONFIG_DIR "/sites.conf"
    };

    for (int i = 0; i < (int)(sizeof(site_config_paths)/sizeof(site_config_paths[0])); i++) {
        if (waf_load_sites_from_file(&config, site_config_paths[i]) == 0) {
            break;
        }
    }
    
    if (config.site_count == 0) {
        waf_add_site(&config, "demo.local", "web", "127.0.0.1", 9000);
    }
    
    printf("Configured sites (%d):\n", config.site_count);
    printf("┌─────────────────────────────────────────────────────────────┐\n");
    printf("│ %-20s │ %-15s │ %-20s │\n", "Domain", "Backend", "Document Root");
    printf("├─────────────────────────────────────────────────────────────┤\n");
    
    for (int i = 0; i < config.site_count; i++) {
        waf_site_config_t *site = (waf_site_config_t*)&config.sites[i];
        printf("│ %-20s │ %s:%-11d │ %-20s │\n", 
               site->domains[0], 
               site->backend_host, 
               site->backend_port,
               site->document_root);
    }
    
    printf("└─────────────────────────────────────────────────────────────┘\n");
    
    return 0;
}

/* ============================================================
 * 配置校验（等价 `nginx -t`）：`bileiwaf check` / `bileiwaf -t`
 * 校验 waf.conf 与 sites.conf 以及 config/sites 下各站点配置：
 * 端口/线程数范围、必需项、重复域名、后端地址、HTTPS 证书可读且配对、
 * 纯静态站点文档根是否存在。有错误时退出码 1。
 * ============================================================ */
static int g_chk_err = 0, g_chk_warn = 0;

static void chk_msg(int is_err, const char *file, int line, const char *fmt, ...) {
    va_list ap;
    fflush(stdout);   /* 保证错误与进度输出顺序一致 */
    if (line > 0) fprintf(stderr, "waf: [%s] %s:%d: ", is_err ? "emerg" : "warn", file, line);
    else          fprintf(stderr, "waf: [%s] %s: ", is_err ? "emerg" : "warn", file);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    if (is_err) g_chk_err++; else g_chk_warn++;
}

static const char *chk_find_waf_conf(char *out, size_t outsz) {
    static char home_conf[512];
    const char *paths[6];
    int n = 0;
    paths[n++] = "config/waf.conf";
    const char *home = getenv("WAF_HOME");
    if (home && home[0]) {
        snprintf(home_conf, sizeof(home_conf), "%s/config/waf.conf", home);
        paths[n++] = home_conf;
    }
    paths[n++] = WAF_PREFIX "/config/waf.conf";
    paths[n++] = "/etc/waf/waf.conf";
    paths[n++] = "/opt/waf/config/waf.conf";
    for (int i = 0; i < n; i++) {
        if (access(paths[i], R_OK) == 0) {
            snprintf(out, outsz, "%s", paths[i]);
            return out;
        }
    }
    return NULL;
}

/* 默认自签证书路径：由 waf 启动脚本首次启动时自动生成 */
static int chk_is_autogen_cert(const char *cert) {
    return !strcmp(cert, "certs/server.pem") || !strcmp(cert, "certs/server.crt");
}

/* 校验证书/私钥可读且配对；err 返回原因 */
static int chk_cert_pair(const char *cert, const char *key, char *err, size_t errsz) {
#if defined(USE_OPENSSL)
    BIO *bc = BIO_new_file(cert, "r");
    if (!bc) { snprintf(err, errsz, "证书文件不可读: %s", cert); return -1; }
    X509 *x = PEM_read_bio_X509(bc, NULL, NULL, NULL);
    BIO_free(bc);
    if (!x) { snprintf(err, errsz, "证书不是有效 PEM: %s", cert); return -1; }

    BIO *bk = BIO_new_file(key, "r");
    EVP_PKEY *p = bk ? PEM_read_bio_PrivateKey(bk, NULL, NULL, NULL) : NULL;
    if (bk) BIO_free(bk);
    if (!p) { X509_free(x); snprintf(err, errsz, "私钥不可读或格式错误: %s", key); return -1; }

    int ok = X509_check_private_key(x, p);
    EVP_PKEY_free(p);
    X509_free(x);
    if (!ok) { snprintf(err, errsz, "证书与私钥不匹配: %s / %s", cert, key); return -1; }
    return 0;
#else
    (void)cert; (void)key;
    snprintf(err, errsz, "未启用 OpenSSL 支持，跳过证书校验");
    return 0;
#endif
}

/* 校验站点配置文件；seen/seen_n 用于跨站点重复域名检测 */
static void chk_site_file(const char *path, char seen[][256], int *seen_n, int max_seen) {
    FILE *fp = fopen(path, "r");
    if (!fp) { chk_msg(1, path, 0, "站点配置文件不存在或不可读"); return; }

    char section[64] = "";
    char line[1024];
    int lineno = 0;
    char domains[8][256]; int ndom = 0;
    char bhost[256] = "", docroot[512] = "", cert[512] = "", key[512] = "";
    int bport = -1, enabled = 1, ssl_en = 0;
    int site_lines[8] = {0};

    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        char *t = waf_trim(line);
        if (!*t || *t == '#' || *t == ';') continue;
        if (*t == '[') {
            char *e = strchr(t, ']');
            if (!e) { chk_msg(1, path, lineno, "节名缺少 ']'"); continue; }
            *e = '\0';
            snprintf(section, sizeof(section), "%s", t + 1);
            continue;
        }
        char *eq = strchr(t, '=');
        if (!eq) { chk_msg(1, path, lineno, "缺少 '=': %s", t); continue; }
        *eq = '\0';
        char *k = waf_trim(t), *v = waf_trim(eq + 1);

        if (!strcmp(section, "site")) {
            if (!strcmp(k, "domain") || !strcmp(k, "domains")) {
                if (ndom < 8) {
                    snprintf(domains[ndom], sizeof(domains[0]), "%s", v);
                    site_lines[ndom] = lineno;
                    ndom++;
                } else {
                    chk_msg(0, path, lineno, "域名超过 8 个，其余将被忽略");
                }
            } else if (!strcmp(k, "backend_host")) {
                snprintf(bhost, sizeof(bhost), "%s", v);
            } else if (!strcmp(k, "backend_port")) {
                for (char *c = v; *c; c++)
                    if (!isdigit((unsigned char)*c)) { chk_msg(1, path, lineno, "backend_port 非数字: %s", v); break; }
                bport = atoi(v);
            } else if (!strcmp(k, "document_root")) {
                snprintf(docroot, sizeof(docroot), "%s", v);
            } else if (!strcmp(k, "enabled")) {
                enabled = atoi(v);
            }
        } else if (!strcmp(section, "ssl")) {
            if (!strcmp(k, "enabled")) ssl_en = atoi(v);
            else if (!strcmp(k, "cert_file")) snprintf(cert, sizeof(cert), "%s", v);
            else if (!strcmp(k, "key_file")) snprintf(key, sizeof(key), "%s", v);
        }
    }
    fclose(fp);

    if (ndom == 0) { chk_msg(1, path, 0, "[site] 段缺少 domain"); return; }
    if (!strcmp(domains[0], "")) chk_msg(1, path, site_lines[0], "domain 为空");
    if (bport < 0) chk_msg(1, path, 0, "[site] 段缺少 backend_port（纯静态站点请显式写 0）");
    else if (bport > 65535) chk_msg(1, path, 0, "backend_port 超出范围: %d", bport);
    if (!bhost[0]) chk_msg(1, path, 0, "[site] 段缺少 backend_host");

    /* 纯静态站点：backend_port = 0 时 document_root 必须存在 */
    if (bport == 0) {
        if (!docroot[0]) chk_msg(1, path, 0, "静态站点（backend_port=0）必须配置 document_root");
        else if (access(docroot, R_OK) != 0) {
            char alt[600];
            const char *wh = getenv("WAF_HOME");
            int ok = 0;
            if (wh && wh[0] && docroot[0] != '/') {
                snprintf(alt, sizeof(alt), "%s/%s", wh, docroot);
                if (access(alt, R_OK) == 0) ok = 1;
            }
            if (!ok) chk_msg(1, path, 0, "document_root 不存在或不可读: %s", docroot);
        }
    }

    if (!enabled) return;   /* 停用站点不参与后续校验 */

    if (ssl_en) {
        /* 两者都留空表示复用 waf.conf 的全局证书（默认自签），属合法配置 */
        if (!cert[0] != !key[0])
            chk_msg(1, path, 0, "[ssl] enabled=1 时 cert_file 与 key_file 必须成对配置");
        else if (cert[0] && key[0]) {
            char err[600];
            if (chk_cert_pair(cert, key, err, sizeof(err)) != 0)
                chk_msg(1, path, 0, "%s", err);
        }
    }

    /* 重复域名 */
    for (int i = 0; i < ndom; i++) {
        if (!domains[i][0]) continue;
        for (int j = 0; j < *seen_n; j++)
            if (!strcasecmp(seen[j], domains[i]))
                chk_msg(1, path, site_lines[i], "域名重复: %s（与其它站点冲突）", domains[i]);
        if (*seen_n < max_seen) {
            snprintf(seen[*seen_n], 256, "%s", domains[i]);
            (*seen_n)++;
        }
    }
}

static int check_config(void) {
    char conf[600];
    const char *found = chk_find_waf_conf(conf, sizeof(conf));
    printf("[check] 壁垒WAF 配置校验\n");

    if (!found) {
        chk_msg(1, "config/waf.conf", 0, "找不到配置文件（已查找 CWD、$WAF_HOME、%s/config、/etc/waf、/opt/waf/config）", WAF_PREFIX);
    } else {
        printf("[check] 主配置: %s\n", found);
        FILE *fp = fopen(found, "r");
        char line[1024];
        int lineno = 0;
        int ssl_cert_set = 0, ssl_key_set = 0;
        char cert[512] = "", key[512] = "", rules_dir[512] = "rules", log_dir[512] = "logs";
        while (fp && fgets(line, sizeof(line), fp)) {
            lineno++;
            char *t = waf_trim(line);
            if (!*t || *t == '#' || *t == ';') continue;
            char *eq = strchr(t, '=');
            if (!eq) continue;
            *eq = '\0';
            char *k = waf_trim(t), *v = waf_trim(eq + 1);
            if (!strcmp(k, "http_port") || !strcmp(k, "https_port") || !strcmp(k, "admin_port")) {
                if (!*v) { chk_msg(1, found, lineno, "%s 为空", k); continue; }
                for (char *c = v; *c; c++)
                    if (!isdigit((unsigned char)*c)) { chk_msg(1, found, lineno, "%s 非数字: %s", k, v); goto next_line; }
                {
                    int p = atoi(v);
                    if (p < 1 || p > 65535) chk_msg(1, found, lineno, "%s 超出范围 1-65535: %d", k, p);
                }
            } else if (!strcmp(k, "worker_threads")) {
                int w = atoi(v);
                if (w < 1 || w > 1024) chk_msg(1, found, lineno, "worker_threads 超出范围 1-1024: %d", w);
            } else if (!strcmp(k, "log_rotate_size") || !strcmp(k, "log_retention_days")) {
                int n = atoi(v);
                if (n < 0) chk_msg(1, found, lineno, "%s 不能为负数: %d", k, n);
            } else if (!strcmp(k, "detection_mode")) {
                if (strcmp(v, "rules") && strcmp(v, "ai") && strcmp(v, "auto"))
                    chk_msg(1, found, lineno, "detection_mode 非法（应为 rules|ai|auto）: %s", v);
            } else if (!strcmp(k, "mode")) {
                if (strcmp(v, "learning") && strcmp(v, "detection") && strcmp(v, "blocking"))
                    chk_msg(1, found, lineno, "mode 非法（应为 learning|detection|blocking）: %s", v);
            } else if (!strcmp(k, "cert_file")) {
                snprintf(cert, sizeof(cert), "%s", v); ssl_cert_set = 1;
            } else if (!strcmp(k, "key_file")) {
                snprintf(key, sizeof(key), "%s", v); ssl_key_set = 1;
            } else if (!strcmp(k, "rules_dir")) {
                snprintf(rules_dir, sizeof(rules_dir), "%s", v);
            } else if (!strcmp(k, "log_dir")) {
                snprintf(log_dir, sizeof(log_dir), "%s", v);
            }
next_line:  ;
        }
        if (fp) fclose(fp);

        if (ssl_cert_set != ssl_key_set)
            chk_msg(1, found, 0, "cert_file 与 key_file 必须成对配置");
        else if (ssl_cert_set && cert[0] && key[0]) {
            char err[600];
            /* 默认自签证书由 `waf start` 首次启动时生成，此处仅提示 */
            if (access(cert, R_OK) != 0 && chk_is_autogen_cert(cert))
                chk_msg(0, found, 0, "证书尚未生成，首次启动将自动创建自签证书: %s", cert);
            else if (chk_cert_pair(cert, key, err, sizeof(err)) != 0)
                chk_msg(1, found, 0, "%s", err);
        }
        if (access(rules_dir, R_OK) != 0) {
            char alt[600]; const char *wh = getenv("WAF_HOME");
            int ok = 0;
            if (wh && wh[0] && rules_dir[0] != '/') {
                snprintf(alt, sizeof(alt), "%s/%s", wh, rules_dir);
                ok = access(alt, R_OK) == 0;
            }
            if (!ok) chk_msg(0, found, 0, "规则目录不存在（启动时自动创建）: %s", rules_dir);
        }
        if (access(log_dir, W_OK) != 0 && access(log_dir, F_OK) == 0)
            chk_msg(0, found, 0, "日志目录不可写: %s", log_dir);
    }

    /* ---- 站点配置 ---- */
    char sites_conf[700];
    char conf_dir[600] = ".";
    if (found) {
        snprintf(conf_dir, sizeof(conf_dir), "%s", found);
        char *slash = strrchr(conf_dir, '/');
        if (slash) *slash = '\0'; else snprintf(conf_dir, sizeof(conf_dir), ".");
    }
    snprintf(sites_conf, sizeof(sites_conf), "%s/sites.conf", conf_dir);

    FILE *sf = fopen(sites_conf, "r");
    if (!sf) {
        chk_msg(0, sites_conf, 0, "未找到 sites.conf，将使用默认站点 demo.local");
    } else {
        char line[1024];
        int lineno = 0, count = 0;
        char seen[512][256];
        int seen_n = 0;
        char sites_dir[700];
        snprintf(sites_dir, sizeof(sites_dir), "%s/sites", conf_dir);
        char section[64] = "";
        while (fgets(line, sizeof(line), sf)) {
            lineno++;
            char *t = waf_trim(line);
            if (!*t || *t == '#' || *t == ';') continue;
            if (*t == '[') {
                char *e = strchr(t, ']');
                if (e) { *e = '\0'; snprintf(section, sizeof(section), "%s", t + 1); }
                continue;
            }
            char *eq = strchr(t, '=');
            if (!eq || strcmp(section, "sites")) continue;
            *eq = '\0';
            char *k = waf_trim(t), *v = waf_trim(eq + 1);
            if (strcmp(k, "site")) continue;
            char *sp = strchr(v, ' ');
            if (sp) *sp = '\0';   /* site = x.conf disabled */
            char spath[900];
            snprintf(spath, sizeof(spath), "%s/%s", sites_dir, v);
            chk_site_file(spath, seen, &seen_n, 512);
            count++;
        }
        fclose(sf);
        printf("[check] 站点配置: %s（%d 个站点）\n", sites_conf, count);
        if (count == 0) chk_msg(0, sites_conf, 0, "[sites] 段没有任何 site 项");
    }

    fprintf(stderr, "\n");
    if (g_chk_err) {
        fprintf(stderr, "waf: configuration file %s test failed（%d 个错误，%d 个警告）\n",
                found ? found : "config/waf.conf", g_chk_err, g_chk_warn);
        return 1;
    }
    printf("waf: configuration file %s test is successful（%d 个警告）\n",
           found ? found : "config/waf.conf", g_chk_warn);
    return 0;
}

int run_waf(waf_config_t *config, int daemonize) {
    pid_t existing_pid;
    if (read_pid_file(&existing_pid) == 0 && is_process_running(existing_pid)) {
        fprintf(stderr, "WAF is already running (PID: %d)\n", existing_pid);
        return 1;
    }
    
    // 切换工作目录以保证相对路径（rules/logs/config）一致解析：
    //   1) $WAF_HOME 最高优先级（systemd / start.sh / 便携发行包均显式设置）
    //   2) 无 WAF_HOME 但 CWD 下存在 config/sites.conf：保持原地
    //      （便携包内直接执行二进制的场景，不得误读 /opt/waf 生产配置）
    //   3) configure --prefix 安装根（make install 后直接运行 bin/bileiwaf 的场景）
    //   4) 最后才回退历史部署根 /opt/waf
    const char *waf_home = getenv("WAF_HOME");
    if (waf_home && waf_home[0]) {
        if (chdir(waf_home) != 0) {
            fprintf(stderr, "Warning: Failed to chdir to WAF_HOME=%s, using current directory\n", waf_home);
        }
    } else if (access("config/sites.conf", R_OK) != 0) {
        static char prefix_sites[512];
        snprintf(prefix_sites, sizeof(prefix_sites), "%s/config/sites.conf", WAF_PREFIX);
        if (access(prefix_sites, R_OK) == 0) {
            chdir(WAF_PREFIX);
        } else if (chdir("/opt/waf") != 0) {
            // If /opt/waf doesn't exist, try to use current directory
            fprintf(stderr, "Warning: Failed to chdir to /opt/waf, using current directory\n");
        }
    }
    
    if (daemonize) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("Failed to fork");
            return -1;
        }
        if (pid > 0) {
            write_pid_file(pid);
            printf("WAF started in background (PID: %d)\n", pid);
            return 0;
        }
        
        setsid();
        umask(0);
        
        FILE *fp = fopen("/dev/null", "r");
        FILE *fp2 = fopen("/dev/null", "w");
        dup2(fileno(fp), STDIN_FILENO);
        dup2(fileno(fp2), STDOUT_FILENO);
        dup2(fileno(fp2), STDERR_FILENO);
    }
    
    if (waf_init(config) != 0) {
        fprintf(stderr, "Failed to initialize WAF\n");
        return 1;
    }
    
    if (!daemonize) {
        write_pid_file(getpid());
    }
    
    if (waf_start() != 0) {
        fprintf(stderr, "Failed to start WAF\n");
        return 1;
    }
    
    return 0;
}

char* get_backend_pid_path(const char *domain) {
    static char path[256];
    char safe_domain[128];
    const char *d = domain;
    char *s = safe_domain;
    
    while (*d && s < safe_domain + sizeof(safe_domain) - 1) {
        if (*d == '.') {
            *s++ = '-';
        } else {
            *s++ = *d;
        }
        d++;
    }
    *s = '\0';
    
    snprintf(path, sizeof(path), "%s/waf-backend-%s.pid", BACKEND_PID_DIR, safe_domain);
    return path;
}

int load_sites_for_backend(waf_config_t *config) {
    memset(config, 0, sizeof(waf_config_t));
    config->http_port = WAF_DEFAULT_HTTP_PORT;
    config->https_port = WAF_DEFAULT_HTTPS_PORT;
    config->backend_port = WAF_DEFAULT_BACKEND_PORT;
    strcpy(config->backend_host, WAF_DEFAULT_BACKEND_HOST);
    strcpy(config->log_dir, "logs");
    strcpy(config->rules_dir, "rules");
    
    waf_sites_init(config);
    
    const char *site_config_paths[] = {
        WAF_CONFIG_DIR "/sites.conf"
    };

    for (int i = 0; i < (int)(sizeof(site_config_paths)/sizeof(site_config_paths[0])); i++) {
        if (waf_load_sites_from_file(config, site_config_paths[i]) == 0) {
            break;
        }
    }
    
    if (config->site_count == 0) {
        waf_add_site(config, "demo.local", "web", "127.0.0.1", 9000);
    }
    
    return 0;
}

int start_backend(const char *domain) {
    waf_config_t config;
    load_sites_for_backend(&config);
    
    waf_site_config_t *site = waf_find_site(&config, domain);
    if (!site) {
        fprintf(stderr, "Site not found: %s\n", domain);
        return -1;
    }
    
    char *pid_path = get_backend_pid_path(domain);
    
    pid_t existing_pid = 0;
    FILE *fp = fopen(pid_path, "r");
    if (fp) {
        fscanf(fp, "%d", &existing_pid);
        fclose(fp);
    }
    
    if (existing_pid > 0 && kill(existing_pid, 0) == 0) {
        printf("Backend for %s is already running (PID: %d)\n", domain, existing_pid);
        return 0;
    }
    
    mkdir(BACKEND_PID_DIR, 0755);
    mkdir(BACKEND_LOG_DIR, 0755);
    
    char log_path[256];
    snprintf(log_path, sizeof(log_path), "%s/waf-backend-%s.log", BACKEND_LOG_DIR, domain);
    
    pid_t pid = fork();
    if (pid < 0) {
        perror("Failed to fork");
        return -1;
    }
    
    if (pid == 0) {
        int fd = open("/dev/null", O_RDONLY);
        dup2(fd, STDIN_FILENO);
        
        fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            fd = open("/dev/null", O_WRONLY);
        }
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", site->backend_port);
        
        execl(BACKEND_BINARY, BACKEND_BINARY, port_str, (char*)NULL);
        exit(1);
    }
    
    sleep(1);
    
    if (kill(pid, 0) == 0) {
        fp = fopen(pid_path, "w");
        if (fp) {
            fprintf(fp, "%d\n", pid);
            fclose(fp);
        }
        printf("Backend for %s started (PID: %d, port: %d)\n", domain, pid, site->backend_port);
        return 0;
    } else {
        fprintf(stderr, "Failed to start backend for %s\n", domain);
        return -1;
    }
}

int stop_backend(const char *domain) {
    char *pid_path = get_backend_pid_path(domain);
    
    pid_t pid = 0;
    FILE *fp = fopen(pid_path, "r");
    if (!fp) {
        printf("Backend for %s is not running\n", domain);
        return 0;
    }
    
    fscanf(fp, "%d", &pid);
    fclose(fp);
    
    if (pid > 0 && kill(pid, 0) == 0) {
        kill(pid, SIGTERM);
        sleep(1);
        
        if (kill(pid, 0) == 0) {
            kill(pid, SIGKILL);
        }
    }
    
    unlink(pid_path);
    printf("Backend for %s stopped\n", domain);
    return 0;
}

int status_backend(const char *domain) {
    waf_config_t config;
    load_sites_for_backend(&config);
    
    waf_site_config_t *site = waf_find_site(&config, domain);
    if (!site) {
        fprintf(stderr, "Site not found: %s\n", domain);
        return -1;
    }
    
    char *pid_path = get_backend_pid_path(domain);
    
    pid_t pid = 0;
    FILE *fp = fopen(pid_path, "r");
    if (!fp) {
        printf("%s: Not running\n", domain);
        return 0;
    }
    
    fscanf(fp, "%d", &pid);
    fclose(fp);
    
    if (pid > 0 && kill(pid, 0) == 0) {
        printf("%s: Running (PID: %d, port: %d)\n", domain, pid, site->backend_port);
    } else {
        unlink(pid_path);
        printf("%s: Not running\n", domain);
    }
    
    return 0;
}

int start_all_backends(void) {
    waf_config_t config;
    load_sites_for_backend(&config);
    
    printf("Starting all backend services...\n");
    
    for (int i = 0; i < config.site_count; i++) {
        waf_site_config_t *site = (waf_site_config_t*)&config.sites[i];
        start_backend(site->domains[0]);
    }
    
    return 0;
}

int stop_all_backends(void) {
    printf("Stopping all backend services...\n");
    
    DIR *dir = opendir(BACKEND_PID_DIR);
    if (!dir) {
        printf("No backend services running\n");
        return 0;
    }
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "waf-backend-", 13) == 0) {
            char pid_path[256];
            snprintf(pid_path, sizeof(pid_path), "%s/%s", BACKEND_PID_DIR, entry->d_name);
            
            pid_t pid = 0;
            FILE *fp = fopen(pid_path, "r");
            if (fp) {
                fscanf(fp, "%d", &pid);
                fclose(fp);
            }
            
            if (pid > 0 && kill(pid, 0) == 0) {
                kill(pid, SIGTERM);
                sleep(0.5);
                if (kill(pid, 0) == 0) {
                    kill(pid, SIGKILL);
                }
            }
            
            char domain[128];
            strncpy(domain, entry->d_name + 13, sizeof(domain) - 1);
            domain[sizeof(domain) - 1] = '\0';
            
            for (char *p = domain; *p; p++) {
                if (*p == '-') *p = '.';
            }
            
            char *dot = strrchr(domain, '.');
            if (dot) *dot = '\0';
            
            unlink(pid_path);
            printf("Backend for %s stopped\n", domain);
        }
    }
    
    closedir(dir);
    return 0;
}

int status_all_backends(void) {
    waf_config_t config;
    load_sites_for_backend(&config);
    
    printf("Backend status for all sites:\n");
    
    for (int i = 0; i < config.site_count; i++) {
        waf_site_config_t *site = (waf_site_config_t*)&config.sites[i];
        status_backend(site->domains[0]);
    }
    
    return 0;
}

int handle_backend_command(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s backend <subcommand> [site]\n", argv[0]);
        printf("\nSubcommands:\n");
        printf("  start <site>      Start backend for specified site\n");
        printf("  stop <site>       Stop backend for specified site\n");
        printf("  status <site>     Show status of backend for specified site\n");
        printf("  start-all         Start backends for all sites\n");
        printf("  stop-all          Stop backends for all sites\n");
        printf("  status-all        Show status of all backends\n");
        return 1;
    }
    
    const char *subcmd = argv[2];
    
    if (strcmp(subcmd, "start") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Please specify site name\n");
            return 1;
        }
        return start_backend(argv[3]);
    }
    
    if (strcmp(subcmd, "stop") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Please specify site name\n");
            return 1;
        }
        return stop_backend(argv[3]);
    }
    
    if (strcmp(subcmd, "status") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Please specify site name\n");
            return 1;
        }
        return status_backend(argv[3]);
    }
    
    if (strcmp(subcmd, "start-all") == 0) {
        return start_all_backends();
    }
    
    if (strcmp(subcmd, "stop-all") == 0) {
        return stop_all_backends();
    }
    
    if (strcmp(subcmd, "status-all") == 0) {
        return status_all_backends();
    }
    
    fprintf(stderr, "Unknown backend subcommand: %s\n", subcmd);
    fprintf(stderr, "Use 'waf backend help' for usage information\n");
    return 1;
}

int load_waf_config(waf_config_t *config) {
    /* 查找顺序：CWD → $WAF_HOME → configure 安装前缀 → /etc/waf → /opt/waf */
    static char home_waf_conf[512];
    home_waf_conf[0] = '\0';
    {
        const char *home = getenv("WAF_HOME");
        if (home && home[0])
            snprintf(home_waf_conf, sizeof(home_waf_conf), "%s/config/waf.conf", home);
    }
    const char *config_paths[] = {
        "config/waf.conf",
        home_waf_conf,          /* WAF_HOME 未设置时为空串，fopen 失败后继续下一项 */
        WAF_PREFIX "/config/waf.conf",
        "/etc/waf/waf.conf",
        "/opt/waf/config/waf.conf",
        NULL
    };
    
    for (int i = 0; config_paths[i]; i++) {
        FILE *fp = fopen(config_paths[i], "r");
        if (fp) {
            char line[1024];
            while (fgets(line, sizeof(line), fp)) {
                char *trimmed = waf_trim(line);
                if (strncmp(trimmed, "cert_file = ", 12) == 0) {
                    strncpy(config->cert_file, trimmed + 12, sizeof(config->cert_file) - 1);
                } else if (strncmp(trimmed, "key_file = ", 11) == 0) {
                    strncpy(config->key_file, trimmed + 11, sizeof(config->key_file) - 1);
                } else if (strncmp(trimmed, "worker_threads = ", 17) == 0) {
                    config->worker_threads = atoi(trimmed + 17);
                } else if (strncmp(trimmed, "detection_mode = ", 17) == 0) {
                    const char *mode_val = trimmed + 17;
                    if (strcmp(mode_val, "rules") == 0) {
                        config->detection_mode = DETECTION_MODE_RULES;
                    } else if (strcmp(mode_val, "ai") == 0) {
                        config->detection_mode = DETECTION_MODE_AI;
                    } else {
                        /* auto / both / 其他未识别值均按 AUTO（规则+AI 双重检测） */
                        config->detection_mode = DETECTION_MODE_AUTO;
                    }
                } else if (strncmp(trimmed, "http_port = ", 12) == 0) {
                    config->http_port = atoi(trimmed + 12);
                } else if (strncmp(trimmed, "https_port = ", 13) == 0) {
                    config->https_port = atoi(trimmed + 13);
                } else if (strncmp(trimmed, "backend_host = ", 15) == 0) {
                    strncpy(config->backend_host, trimmed + 15, sizeof(config->backend_host) - 1);
                } else if (strncmp(trimmed, "backend_port = ", 15) == 0) {
                    config->backend_port = atoi(trimmed + 15);
                } else if (strncmp(trimmed, "log_dir = ", 9) == 0) {
                    strncpy(config->log_dir, waf_trim(trimmed + 9), sizeof(config->log_dir) - 1);
                } else if (strncmp(trimmed, "error_404_page = ", 17) == 0) {
                    strncpy(config->error_404_page, waf_trim(trimmed + 17), sizeof(config->error_404_page) - 1);
                } else if (strncmp(trimmed, "log_rotate_size = ", 18) == 0) {
                    config->log_rotate_size_mb = atoi(waf_trim(trimmed + 18));
                } else if (strncmp(trimmed, "log_retention_days = ", 21) == 0) {
                    config->log_retention_days = atoi(waf_trim(trimmed + 21));
                } else if (strncmp(trimmed, "rules_dir = ", 11) == 0) {
                    strncpy(config->rules_dir, waf_trim(trimmed + 11), sizeof(config->rules_dir) - 1);
                } else if (strncmp(trimmed, "mode = ", 7) == 0) {
                    const char *mode_val = trimmed + 7;
                    if (strcmp(mode_val, "learning") == 0) {
                        config->mode = WAF_MODE_LEARNING;
                    } else if (strcmp(mode_val, "detection") == 0) {
                        config->mode = WAF_MODE_DETECTION;
                    } else {
                        config->mode = WAF_MODE_BLOCKING;
                    }
                } else if (strncmp(trimmed, "ai_ensemble = ", 14) == 0) {
                    const char *ensemble_val = trimmed + 14;
                    if (strcmp(ensemble_val, "none") == 0) {
                        config->ai_ensemble = AI_ENSEMBLE_NONE;
                    } else if (strcmp(ensemble_val, "voting") == 0) {
                        config->ai_ensemble = AI_ENSEMBLE_VOTING;
                    } else if (strcmp(ensemble_val, "cascade") == 0) {
                        config->ai_ensemble = AI_ENSEMBLE_CASCADE;
                    } else {
                        config->ai_ensemble = AI_ENSEMBLE_BLENDING;
                    }
                } else if (strncmp(trimmed, "ai_threshold = ", 15) == 0) {
                    config->ai_threshold = atof(trimmed + 15);
                } else if (strncmp(trimmed, "ai_ensemble_threshold = ", 24) == 0) {
                    config->ai_ensemble_threshold = atof(trimmed + 24);
                } else if (strncmp(trimmed, "ai_cnn_weight = ", 16) == 0) {
                    config->ai_cnn_weight = atof(trimmed + 16);
                } else if (strncmp(trimmed, "ai_model_weights = ", 19) == 0) {
                    char *weights_str = trimmed + 19;
                    char *token = strtok(weights_str, ",");
                    int idx = 0;
                    while (token && idx < MAX_MODELS) {
                        config->ai_model_weights[idx] = atof(waf_trim(token));
                        token = strtok(NULL, ",");
                        idx++;
                    }
                } else if (strncmp(trimmed, "ai_whitelist_domains = ", 23) == 0) {
                    strncpy(config->ai_whitelist_domains, trimmed + 23, sizeof(config->ai_whitelist_domains) - 1);
                } else if (strncmp(trimmed, "ai_shadow_mode = ", 17) == 0) {
                    const char *v = trimmed + 17;
                    config->ai_shadow_mode = (strcmp(v, "on") == 0 || strcmp(v, "1") == 0 ||
                                              strcmp(v, "true") == 0 || strcmp(v, "yes") == 0);
                } else if (strncmp(trimmed, "ai_auto_learn = ", 16) == 0) {
                    const char *v = trimmed + 16;
                    config->ai_auto_learn = (strcmp(v, "on") == 0 || strcmp(v, "1") == 0 ||
                                             strcmp(v, "true") == 0 || strcmp(v, "yes") == 0);
                } else if (strncmp(trimmed, "ai_guard_enabled = ", 19) == 0) {
                    const char *v = trimmed + 19;
                    config->ai_guard_enabled = (strcmp(v, "on") == 0 || strcmp(v, "1") == 0 ||
                                                strcmp(v, "true") == 0 || strcmp(v, "yes") == 0);
                } else if (strncmp(trimmed, "ai_guard_min_occurrences = ", 27) == 0) {
                    config->ai_guard_min_occ = atoi(trimmed + 27);
                } else if (strncmp(trimmed, "ai_guard_min_confidence = ", 26) == 0) {
                    config->ai_guard_min_conf = atoi(trimmed + 26);
                } else if (strncmp(trimmed, "ai_guard_max_rules = ", 21) == 0) {
                    config->ai_guard_max_rules = atoi(trimmed + 21);
                } else if (strncmp(trimmed, "ai_guard_max_white_fp = ", 24) == 0) {
                    config->ai_guard_max_white_fp = atoi(trimmed + 24);
                } else if (strncmp(trimmed, "ai_white_list = ", 16) == 0) {
                    strncpy(config->ai_white_list, trimmed + 16, sizeof(config->ai_white_list) - 1);
                } else if (strncmp(trimmed, "ai_learned_rules = ", 19) == 0) {
                    strncpy(config->ai_learned_rules, trimmed + 19, sizeof(config->ai_learned_rules) - 1);
                }
            }
            fclose(fp);
            return 0;
        }
    }
    return -1;
}

void print_cert_info(const char *cert_file) {
    if (!cert_file || !cert_file[0]) return;
    
    FILE *fp = fopen(cert_file, "r");
    if (!fp) return;
    
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!cert) return;
    
    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);
    
    char before_str[64] = {0};
    char after_str[64] = {0};
    
    if (not_before) {
        ASN1_TIME_print(BIO_new_fp(stdout, BIO_NOCLOSE), not_before);
        printf("\n");
    }
    
    X509_free(cert);
}

int cert_status(void) {
    printf("SSL Certificate Status:\n");
    printf("======================\n\n");
    
    waf_config_t config;
    memset(&config, 0, sizeof(config));
    config.auto_add_www = 0;
    waf_sites_init(&config);
    
    const char *site_config_paths[] = {
        WAF_CONFIG_DIR "/sites.json",
        WAF_CONFIG_DIR "/sites.conf",
        NULL
    };
    
    for (int i = 0; site_config_paths[i]; i++) {
        if (waf_load_sites_from_file(&config, site_config_paths[i]) == 0) {
            break;
        }
    }
    
    if (config.site_count == 0) {
        printf("No sites configured.\n");
        return 0;
    }
    
    for (int i = 0; i < config.site_count; i++) {
        waf_site_config_t *site = &config.sites[i];
        
        printf("Site: %s", site->domains[0]);
        for (int j = 1; j < site->domain_count; j++) {
            printf(" %s", site->domains[j]);
        }
        printf("\n");
        
        printf("  Document Root: %s\n", site->document_root);
        printf("  Backend: %s:%d\n", site->backend_host, site->backend_port);
        
        if (site->proxy_enabled && site->proxy_pass[0]) {
            printf("  Proxy: %s (timeout: %ds)\n", site->proxy_pass, site->proxy_timeout);
        }
        
        if (site->language[0]) {
            printf("  Language: %s\n", site->language);
        }
        
        if (site->cert_file[0] && site->key_file[0]) {
            printf("  Certificate: %s\n", site->cert_file);
            printf("  Key: %s\n", site->key_file);
            
            struct stat st;
            int cert_ok = stat(site->cert_file, &st) == 0;
            int key_ok = stat(site->key_file, &st) == 0;
            
            if (cert_ok && key_ok) {
                printf("  Status: Valid\n");
                
                FILE *fp = fopen(site->cert_file, "r");
                if (fp) {
                    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
                    fclose(fp);
                    
                    if (cert) {
                        ASN1_TIME *not_before = X509_get_notBefore(cert);
                        ASN1_TIME *not_after = X509_get_notAfter(cert);
                        
                        if (not_before) {
                            printf("  Valid from: ");
                            ASN1_TIME_print(BIO_new_fp(stdout, BIO_NOCLOSE), not_before);
                            printf("\n");
                        }
                        if (not_after) {
                            printf("  Expires on:  ");
                            ASN1_TIME_print(BIO_new_fp(stdout, BIO_NOCLOSE), not_after);
                            printf("\n");
                            
                            time_t now = time(NULL);
                            BIO *bio = BIO_new(BIO_s_mem());
                            ASN1_TIME_print(bio, not_after);
                            char after_str[64] = {0};
                            BIO_read(bio, after_str, sizeof(after_str)-1);
                            BIO_free(bio);
                            
                            struct tm expire_tm = {0};
                            if (strptime(after_str, "%b %d %H:%M:%S %Y GMT", &expire_tm)) {
                                time_t expire_time = mktime(&expire_tm);
                                if (expire_time > now) {
                                    long days_left = (expire_time - now) / (24 * 60 * 60);
                                    printf("  Days remaining: %ld\n", days_left);
                                } else {
                                    printf("  Days remaining: EXPIRED\n");
                                }
                            }
                        }
                        X509_free(cert);
                    }
                }
            } else if (cert_ok) {
                printf("  Status: Certificate found, key missing\n");
            } else if (key_ok) {
                printf("  Status: Key found, certificate missing\n");
            } else {
                printf("  Status: Certificate and key missing\n");
            }
        } else {
            printf("  Certificate: Not configured\n");
            printf("  Key: Not configured\n");
            printf("  Status: No certificate\n");
        }
        
        printf("\n");
    }
    
    printf("Default cert directory: %s/\n", WAF_DEFAULT_CERT_DIR);
    
    return 0;
}

int cert_set(const char *domain, const char *cert_path, const char *key_path) {
    struct stat st;
    int cert_ok = stat(cert_path, &st) == 0;
    int key_ok = stat(key_path, &st) == 0;
    
    if (!cert_ok) {
        fprintf(stderr, "Certificate file not found: %s\n", cert_path);
        return 1;
    }
    if (!key_ok) {
        fprintf(stderr, "Key file not found: %s\n", key_path);
        return 1;
    }
    
    waf_config_t config;
    memset(&config, 0, sizeof(config));
    config.auto_add_www = 1;
    waf_sites_init(&config);
    
    const char *site_config_paths[] = {
        WAF_CONFIG_DIR "/sites.json",
        WAF_CONFIG_DIR "/sites.conf",
        NULL
    };
    
    for (int i = 0; site_config_paths[i]; i++) {
        if (waf_load_sites_from_file(&config, site_config_paths[i]) == 0) {
            break;
        }
    }
    
    waf_site_config_t *site = waf_find_site(&config, domain);
    if (!site) {
        fprintf(stderr, "Site not found: %s\n", domain);
        return 1;
    }
    
    waf_set_site_cert(&config, domain, cert_path, key_path);
    
    if (strncmp(domain, "www.", 4) != 0) {
        char www_domain[256];
        snprintf(www_domain, sizeof(www_domain), "www.%s", domain);
        
        waf_site_config_t *www_site = waf_find_site(&config, www_domain);
        if (www_site) {
            int already_same = (strcmp(www_site->cert_file, cert_path) == 0 && 
                               strcmp(www_site->key_file, key_path) == 0);
            if (!already_same) {
                waf_set_site_cert(&config, www_domain, cert_path, key_path);
                printf("Certificate also set for www domain: %s\n", www_domain);
            }
        }
    }
    
    for (int i = 0; site_config_paths[i]; i++) {
        if (waf_save_sites_to_file(&config, site_config_paths[i]) == 0) {
            printf("Certificate configuration updated for site: %s\n", domain);
            printf("  Certificate: %s\n", cert_path);
            printf("  Key: %s\n", key_path);
            printf("  Config file: %s\n", site_config_paths[i]);
            printf("\n");
            printf("Restart WAF for changes to take effect.\n");
            return 0;
        }
    }
    
    fprintf(stderr, "Failed to save site configuration\n");
    return 1;
}

int cert_generate(const char *domain, int days) {
    printf("Generating self-signed certificate...\n");
    
    mkdir(WAF_DEFAULT_CERT_DIR, 0755);
    
    char cert_path[512];
    char key_path[512];
    char cn[512];
    char san_file[512];
    char www_domain[256];
    
    if (domain && domain[0]) {
        snprintf(cert_path, sizeof(cert_path), "%s/%s.crt", WAF_DEFAULT_CERT_DIR, domain);
        snprintf(key_path, sizeof(key_path), "%s/%s.key", WAF_DEFAULT_CERT_DIR, domain);
        snprintf(san_file, sizeof(san_file), "%s/%s.cnf", WAF_DEFAULT_CERT_DIR, domain);
        
        if (strncmp(domain, "www.", 4) == 0) {
            snprintf(cn, sizeof(cn), "CN=%s", domain);
        } else {
            snprintf(cn, sizeof(cn), "CN=%s", domain);
            snprintf(www_domain, sizeof(www_domain), "www.%s", domain);
        }
    } else {
        snprintf(cert_path, sizeof(cert_path), "%s/waf.crt", WAF_DEFAULT_CERT_DIR);
        snprintf(key_path, sizeof(key_path), "%s/waf.key", WAF_DEFAULT_CERT_DIR);
        snprintf(san_file, sizeof(san_file), "%s/waf.cnf", WAF_DEFAULT_CERT_DIR);
        strncpy(cn, "CN=waf.local", sizeof(cn) - 1);
        www_domain[0] = '\0';
    }
    
    if (days <= 0) {
        days = 365;
    }
    
    if (domain && domain[0] && www_domain[0]) {
        FILE *cnf = fopen(san_file, "w");
        if (cnf) {
            fprintf(cnf, "[req]\ndistinguished_name = req_distinguished_name\nx509_extensions = v3_ca\n\n");
            fprintf(cnf, "[req_distinguished_name]\ncountryName = CN\nstateOrProvinceName = Beijing\nlocalityName = Beijing\norganizationName = WAF\n\n");
            fprintf(cnf, "[v3_ca]\nsubjectAltName = @alt_names\n\n");
            fprintf(cnf, "[alt_names]\nDNS.1 = %s\nDNS.2 = %s\n", domain, www_domain);
            fclose(cnf);
        }
    }
    
    char days_str[16];
    snprintf(days_str, sizeof(days_str), "%d", days);
    
    pid_t pid = fork();
    if (pid == 0) {
        char subj[512];
        if (domain && domain[0]) {
            snprintf(subj, sizeof(subj), "/C=CN/ST=Beijing/L=Beijing/O=WAF/CN=%s", domain);
        } else {
            strncpy(subj, "/C=CN/ST=Beijing/L=Beijing/O=WAF/CN=waf.local", sizeof(subj) - 1);
        }
        
        if (domain && domain[0] && www_domain[0]) {
            char cmd[2048];
            snprintf(cmd, sizeof(cmd), 
                    "openssl req -x509 -newkey rsa:4096 -days %s -nodes -keyout %s -out %s -subj '%s' -addext 'subjectAltName=DNS:%s,DNS:%s'",
                    days_str, key_path, cert_path, subj, domain, www_domain);
            system(cmd);
            exit(0);
        } else {
            execlp("openssl", "openssl", "req", "-x509", "-newkey", "rsa:4096",
                   "-days", days_str, "-nodes", "-keyout", key_path, "-out", cert_path,
                   "-subj", subj,
                   (char*)NULL);
        }
        perror("openssl");
        exit(1);
    }
    
    waitpid(pid, NULL, 0);
    
    struct stat st;
    if (stat(cert_path, &st) == 0 && stat(key_path, &st) == 0) {
        printf("Self-signed certificate generated:\n");
        printf("  Certificate: %s\n", cert_path);
        printf("  Key: %s\n", key_path);
        printf("  Validity: %d days\n", days);
        printf("\n");
        
        if (domain && domain[0]) {
            printf("Run 'waf cert set %s %s %s' to use this certificate.\n", domain, cert_path, key_path);
        } else {
            printf("Run 'waf cert set <domain> %s %s' to use this certificate.\n", cert_path, key_path);
        }
    } else {
        fprintf(stderr, "Failed to generate certificate\n");
        fprintf(stderr, "Please install openssl and try again.\n");
        return 1;
    }
    
    return 0;
}

int cert_deploy_live(void);
int cert_issue(const char *domain) {
    if (!domain) {
        fprintf(stderr, "Please specify domain\n");
        return 1;
    }
    
    printf("Issuing Let's Encrypt certificate for %s...\n", domain);
    printf("\n");
    printf("Let's Encrypt Certificate Info:\n");
    printf("  - Validity period: 90 days (fixed by Let's Encrypt)\n");
    printf("  - Auto-renewal recommended before expiry\n");
    printf("\n");
    printf("Requirements:\n");
    printf("  1. Port 80 must be available (WAF will be stopped temporarily)\n");
    printf("  2. Domain %s must resolve to this server's IP\n", domain);
    printf("  3. certbot must be installed\n");
    printf("\n");
    
    if (system("which certbot > /dev/null 2>&1") != 0) {
        printf("certbot not found!\n");
        printf("\n");
        printf("You have two options:\n");
        printf("\n");
        printf("Option 1: Install certbot and use Let's Encrypt\n");
        printf("  yum install -y certbot\n");
        printf("  then run: waf cert issue %s\n", domain);
        printf("\n");
        printf("Option 2: Generate self-signed certificate (for testing)\n");
        printf("  waf cert generate %s\n", domain);
        printf("  then run: waf cert set %s certs/%s.crt certs/%s.key\n", domain, domain, domain);
        printf("\n");
        return 1;
    }
    
    printf("Stopping WAF to free port 80...\n");
    if (read_pid_file((pid_t[]){0}) == 0) {
        stop_waf();
    }
    
    char cmd[1024];
    char www_domain[256];
    snprintf(www_domain, sizeof(www_domain), "www.%s", domain);
    snprintf(cmd, sizeof(cmd), 
             "certbot certonly --standalone "
             "-d %s -d %s "
             "--non-interactive "
             "--agree-tos "
             "--email admin@%s", 
             domain, www_domain, domain);
    
    printf("Running certbot...\n");
    int result = system(cmd);
    
    if (result == 0) {
        char cert_file[512];
        char key_file[512];
        snprintf(cert_file, sizeof(cert_file), "%s/%s/fullchain.pem", CERT_DIR, domain);
        snprintf(key_file, sizeof(key_file), "%s/%s/privkey.pem", CERT_DIR, domain);
        
        struct stat st;
        if (stat(cert_file, &st) == 0 && stat(key_file, &st) == 0) {
            printf("\n");
            printf("✅ Let's Encrypt certificate issued successfully!\n");
            printf("   Certificate expires in 90 days\n");
            printf("\n");
            cert_deploy_live();
            cert_set(domain, cert_file, key_file);
            return 0;
        } else {
            fprintf(stderr, "Certificate files not found after issuing\n");
            return 1;
        }
    } else {
        fprintf(stderr, "Failed to issue Let's Encrypt certificate\n");
        return 1;
    }
}

/* 把 /etc/letsencrypt/live/<域名>/ 下已续期的证书同步到 WAF 证书目录
 * certs/letsencrypt/<域名>/（站点配置实际引用的路径） */
int cert_deploy_live(void) {
    DIR *dir = opendir(CERT_DIR);
    if (!dir) {
        printf("No Let's Encrypt live directory found, skip deploy\n");
        return 0;
    }

    int deployed = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char src_cert[512], src_key[512];
        char dst_dir[512], dst_cert[512], dst_key[512];
        snprintf(src_cert, sizeof(src_cert), "%s/%s/fullchain.pem", CERT_DIR, entry->d_name);
        snprintf(src_key, sizeof(src_key), "%s/%s/privkey.pem", CERT_DIR, entry->d_name);

        struct stat st;
        if (stat(src_cert, &st) != 0 || stat(src_key, &st) != 0) continue;

        snprintf(dst_dir, sizeof(dst_dir), "%s/letsencrypt/%s", WAF_DEFAULT_CERT_DIR, entry->d_name);
        snprintf(dst_cert, sizeof(dst_cert), "%s/fullchain.pem", dst_dir);
        snprintf(dst_key, sizeof(dst_key), "%s/privkey.pem", dst_dir);

        if (mkdir(dst_dir, 0755) != 0 && errno != EEXIST) continue;

        char cmd[2048];
        /* 内容相同则跳过，不同才覆盖 */
        snprintf(cmd, sizeof(cmd),
                 "cmp -s '%s' '%s' && cmp -s '%s' '%s' || "
                 "{ cp -f '%s' '%s' && cp -f '%s' '%s' && chmod 600 '%s'; }",
                 src_cert, dst_cert, src_key, dst_key,
                 src_cert, dst_cert, src_key, dst_key, dst_key);
        if (system(cmd) == 0) {
            printf("  Deployed certificate for %s -> %s\n", entry->d_name, dst_cert);
            deployed++;
        } else {
            fprintf(stderr, "  Failed to deploy certificate for %s\n", entry->d_name);
        }
    }
    closedir(dir);

    printf("Deployed %d certificate(s) to %s/letsencrypt/\n", deployed, WAF_DEFAULT_CERT_DIR);
    return deployed;
}

int cert_renew(void) {
    printf("Checking and renewing certificates...\n");
    printf("\n");
    printf("Let's Encrypt Certificate Info:\n");
    printf("  - Validity period: 90 days (fixed by Let's Encrypt)\n");
    printf("  - Auto-renewal is recommended when < 30 days remaining\n");
    printf("\n");

    if (system("which certbot > /dev/null 2>&1") != 0) {
        fprintf(stderr, "certbot not installed\n");
        return 1;
    }

    int waf_running = read_pid_file((pid_t[]){0}) == 0;

    if (waf_running) {
        printf("Stopping WAF to free port 80...\n");
        stop_waf();
        sleep(2);
    }

    int result = system("certbot renew --quiet");
    int exit_code = (result == -1) ? -1 : WEXITSTATUS(result);

    if (exit_code == 0) {
        /* 续期（或确认无需续期）后，把 live 目录的最新证书部署到 WAF 证书目录 */
        printf("\nDeploying certificates to WAF cert directory...\n");
        cert_deploy_live();
    }
    
    if (waf_running) {
        printf("Restarting WAF...\n");
        waf_config_t config = {0};
        config.http_port = WAF_DEFAULT_HTTP_PORT;
        config.https_port = WAF_DEFAULT_HTTPS_PORT;
        config.backend_port = WAF_DEFAULT_BACKEND_PORT;
        config.worker_threads = WAF_WORKER_THREADS;
        config.mode = WAF_MODE_BLOCKING;
        config.detection_mode = WAF_DEFAULT_DETECTION_MODE;
        config.enable_cc_protection = 1;
        config.enable_api_protection = 1;
        config.ssl_enabled = 0;
        config.max_body_size = MAX_BODY_SIZE;
        strcpy(config.backend_host, WAF_DEFAULT_BACKEND_HOST);
        strcpy(config.log_dir, "logs");
        strcpy(config.rules_dir, "rules");
        config.log_rotate_size_mb = WAF_DEFAULT_LOG_ROTATE_MB;
        config.log_retention_days = WAF_DEFAULT_LOG_RETENTION;

        load_waf_config(&config);
        if (config.cert_file[0]) {
            config.ssl_enabled = 1;
        }

        run_waf(&config, 1);
    }
    
    printf("Certificate renewal complete\n");
    return exit_code;
}

int cert_list(void) {
    printf("Installed Let's Encrypt Certificates:\n");
    printf("----------------------------------------\n");
    
    int found = 0;
    DIR *dir = opendir(CERT_DIR);
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] != '.') {
                char cert_path[512];
                char key_path[512];
                snprintf(cert_path, sizeof(cert_path), "%s/%s/fullchain.pem", CERT_DIR, entry->d_name);
                snprintf(key_path, sizeof(key_path), "%s/%s/privkey.pem", CERT_DIR, entry->d_name);
                
                struct stat st;
                if (stat(cert_path, &st) == 0 && stat(key_path, &st) == 0) {
                    found = 1;
                    printf("Domain: %s\n", entry->d_name);
                    printf("  Certificate: %s\n", cert_path);
                    printf("  Private Key: %s\n", key_path);
                    printf("\n");
                }
            }
        }
        closedir(dir);
    }
    
    if (!found) {
        printf("(No Let's Encrypt certificates found)\n");
        printf("\n");
    }
    
    printf("Current WAF Configuration:\n");
    printf("----------------------------------------\n");
    cert_status();
    
    return 0;
}

int cert_auto(void) {
    printf("Auto-configuring SSL certificates...\n");
    printf("===================================\n\n");
    
    waf_config_t config;
    memset(&config, 0, sizeof(config));
    config.auto_add_www = 1;
    waf_sites_init(&config);
    
    const char *site_config_paths[] = {
        WAF_CONFIG_DIR "/sites.json",
        WAF_CONFIG_DIR "/sites.conf",
        NULL
    };
    
    for (int i = 0; site_config_paths[i]; i++) {
        if (waf_load_sites_from_file(&config, site_config_paths[i]) == 0) {
            break;
        }
    }
    
    if (config.site_count == 0) {
        printf("No sites configured.\n");
        printf("Please add sites first using: waf sites add <domain>\n");
        return 1;
    }
    
    if (system("which certbot > /dev/null 2>&1") != 0) {
        printf("certbot not found, generating self-signed certificates...\n\n");
        
        for (int i = 0; i < config.site_count; i++) {
            waf_site_config_t *site = &config.sites[i];
            const char *domain = site->domains[0];
            
            if (site->cert_file[0] && stat(site->cert_file, &(struct stat){0}) == 0) {
                printf("✓ %s already has certificate: %s\n", domain, site->cert_file);
                continue;
            }
            
            printf("Generating certificate for %s...\n", domain);
            cert_generate(domain, 365);
            
            char cert_path[512];
            char key_path[512];
            snprintf(cert_path, sizeof(cert_path), "%s/%s.crt", WAF_DEFAULT_CERT_DIR, domain);
            snprintf(key_path, sizeof(key_path), "%s/%s.key", WAF_DEFAULT_CERT_DIR, domain);
            
            struct stat st;
            if (stat(cert_path, &st) == 0 && stat(key_path, &st) == 0) {
                waf_set_site_cert(&config, domain, cert_path, key_path);
                printf("✓ Certificate configured for %s\n", domain);
            }
        }
        
        for (int i = 0; site_config_paths[i]; i++) {
            if (waf_save_sites_to_file(&config, site_config_paths[i]) == 0) {
                printf("\nConfiguration saved to: %s\n", site_config_paths[i]);
                break;
            }
        }
        
        printf("\nRemember to restart WAF: waf restart\n");
        return 0;
    }
    
    printf("certbot found, checking for Let's Encrypt certificates...\n\n");
    
    int any_issued = 0;
    for (int i = 0; i < config.site_count; i++) {
        waf_site_config_t *site = &config.sites[i];
        const char *domain = site->domains[0];
        
        char le_cert[512];
        char le_key[512];
        snprintf(le_cert, sizeof(le_cert), "/etc/letsencrypt/live/%s/fullchain.pem", domain);
        snprintf(le_key, sizeof(le_key), "/etc/letsencrypt/live/%s/privkey.pem", domain);
        
        struct stat st;
        if (stat(le_cert, &st) == 0 && stat(le_key, &st) == 0) {
            if (strcmp(site->cert_file, le_cert) != 0 || strcmp(site->key_file, le_key) != 0) {
                printf("✓ Found existing Let's Encrypt cert for %s\n", domain);
                waf_set_site_cert(&config, domain, le_cert, le_key);
                any_issued = 1;
            } else {
                printf("✓ %s already using Let's Encrypt certificate\n", domain);
            }
            continue;
        }
        
        printf("Issuing Let's Encrypt certificate for %s...\n", domain);
        int result = cert_issue(domain);
        if (result == 0) {
            any_issued = 1;
        }
    }
    
    if (any_issued) {
        for (int i = 0; site_config_paths[i]; i++) {
            if (waf_save_sites_to_file(&config, site_config_paths[i]) == 0) {
                printf("\nConfiguration saved to: %s\n", site_config_paths[i]);
                break;
            }
        }
    }
    
    printf("\nAuto-configuration complete!\n");
    printf("Restart WAF to apply changes: waf restart\n");
    return 0;
}

int cert_test(const char *domain) {
    printf("Testing SSL certificate configuration...\n");
    printf("=====================================\n\n");
    
    if (!domain) {
        fprintf(stderr, "Please specify domain\n");
        return 1;
    }
    
    waf_config_t config;
    memset(&config, 0, sizeof(config));
    waf_sites_init(&config);
    
    const char *site_config_paths[] = {
        WAF_CONFIG_DIR "/sites.json",
        WAF_CONFIG_DIR "/sites.conf",
        NULL
    };
    
    for (int i = 0; site_config_paths[i]; i++) {
        if (waf_load_sites_from_file(&config, site_config_paths[i]) == 0) {
            break;
        }
    }
    
    waf_site_config_t *site = waf_find_site(&config, domain);
    if (!site) {
        fprintf(stderr, "Site not found: %s\n", domain);
        return 1;
    }
    
    if (!site->cert_file[0] || !site->key_file[0]) {
        printf("❌ Certificate not configured for %s\n", domain);
        return 1;
    }
    
    printf("Domain: %s\n", domain);
    printf("Certificate: %s\n", site->cert_file);
    printf("Key: %s\n", site->key_file);
    printf("\n");
    
    struct stat st;
    int cert_ok = stat(site->cert_file, &st) == 0;
    int key_ok = stat(site->key_file, &st) == 0;
    
    if (!cert_ok) {
        printf("❌ Certificate file not found: %s\n", site->cert_file);
    } else {
        printf("✓ Certificate file exists\n");
    }
    
    if (!key_ok) {
        printf("❌ Key file not found: %s\n", site->key_file);
    } else {
        printf("✓ Key file exists\n");
    }
    
    if (!cert_ok || !key_ok) {
        return 1;
    }
    
    printf("\nVerifying certificate validity...\n");
    
    FILE *fp = fopen(site->cert_file, "r");
    if (!fp) {
        printf("❌ Cannot read certificate file\n");
        return 1;
    }
    
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!cert) {
        printf("❌ Invalid certificate format\n");
        return 1;
    }
    
    ASN1_TIME *not_after = X509_get_notAfter(cert);
    if (not_after) {
        time_t now = time(NULL);
        BIO *bio = BIO_new(BIO_s_mem());
        ASN1_TIME_print(bio, not_after);
        char after_str[64] = {0};
        BIO_read(bio, after_str, sizeof(after_str)-1);
        BIO_free(bio);
        
        struct tm expire_tm = {0};
        if (strptime(after_str, "%b %d %H:%M:%S %Y GMT", &expire_tm)) {
            time_t expire_time = mktime(&expire_tm);
            if (expire_time > now) {
                long days_left = (expire_time - now) / (24 * 60 * 60);
                printf("✓ Certificate valid for %ld more days\n", days_left);
            } else {
                printf("❌ Certificate expired!\n");
                X509_free(cert);
                return 1;
            }
        }
    }
    
    X509_free(cert);
    
    printf("\nRunning openssl verification...\n");
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "openssl x509 -in %s -noout -text > /dev/null 2>&1", site->cert_file);
    if (system(cmd) == 0) {
        printf("✓ Certificate format is valid\n");
    } else {
        printf("❌ Certificate verification failed\n");
        return 1;
    }
    
    snprintf(cmd, sizeof(cmd), "openssl rsa -in %s -check -noout > /dev/null 2>&1", site->key_file);
    if (system(cmd) == 0) {
        printf("✓ Private key format is valid\n");
    } else {
        printf("❌ Private key verification failed\n");
        return 1;
    }
    
    snprintf(cmd, sizeof(cmd), "openssl rsa -in %s -pubout -out /tmp/waf_pub.pem 2>/dev/null && openssl x509 -in %s -pubkey -noout -out /tmp/cert_pub.pem 2>/dev/null && diff /tmp/waf_pub.pem /tmp/cert_pub.pem > /dev/null 2>&1", site->key_file, site->cert_file);
    if (system(cmd) == 0) {
        printf("✓ Certificate and key match\n");
    } else {
        printf("❌ Certificate and key do not match\n");
        return 1;
    }
    
    printf("\n✅ All checks passed!\n");
    printf("Certificate is ready for use.\n");
    
    return 0;
}

int cert_install_cron(void) {
    printf("Installing automatic certificate renewal cron job...\n");
    printf("==================================================\n\n");
    
    if (system("which certbot > /dev/null 2>&1") != 0) {
        fprintf(stderr, "certbot not installed\n");
        return 1;
    }
    
    const char *cron_entry = "0 3 * * * root cd /opt/waf && ./bin/waf cert renew > logs/waf-cert-renew.log 2>&1\n";
    const char *cron_file = "/etc/cron.d/waf-cert-renew";
    
    FILE *fp = fopen(cron_file, "w");
    if (!fp) {
        fprintf(stderr, "Failed to create cron file: %s\n", cron_file);
        return 1;
    }
    
    fprintf(fp, "%s", cron_entry);
    fclose(fp);
    
    printf("✓ Cron job installed at: %s\n", cron_file);
    printf("✓ Certificate renewal scheduled daily at 03:00\n");
    printf("\nCron entry:\n");
    printf("  %s", cron_entry);
    printf("\nLogs will be written to: logs/waf-cert-renew.log\n");
    
    return 0;
}

int cert_dry_run(void) {
    printf("Running dry-run certificate renewal test...\n");
    printf("===========================================\n\n");
    
    if (system("which certbot > /dev/null 2>&1") != 0) {
        fprintf(stderr, "certbot not installed\n");
        return 1;
    }
    
    printf("Running: certbot renew --dry-run\n");
    printf("-------------------------------\n");
    
    int result = system("certbot renew --dry-run");
    
    if (result == 0) {
        printf("\n✅ Dry-run successful! Certificates can be renewed.\n");
        return 0;
    } else {
        printf("\n❌ Dry-run failed. Please check the output above.\n");
        return 1;
    }
}

int cert_revoke(const char *domain) {
    if (!domain) {
        fprintf(stderr, "Please specify domain\n");
        return 1;
    }
    
    printf("Revoking Let's Encrypt certificate for %s...\n", domain);
    printf("==============================================\n\n");
    
    if (system("which certbot > /dev/null 2>&1") != 0) {
        fprintf(stderr, "certbot not installed\n");
        return 1;
    }
    
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "certbot revoke --cert-name %s --delete-after-revoke", domain);
    
    printf("Warning: This will permanently revoke and delete the certificate!\n");
    printf("Are you sure you want to proceed? (y/N) ");
    
    char response[32];
    fgets(response, sizeof(response), stdin);
    if (response[0] != 'y' && response[0] != 'Y') {
        printf("Aborted.\n");
        return 0;
    }
    
    printf("\nRunning: %s\n", cmd);
    int result = system(cmd);
    
    if (result == 0) {
        printf("\n✅ Certificate revoked successfully\n");
        printf("Remember to update your site configuration to use a different certificate.\n");
    } else {
        printf("\n❌ Failed to revoke certificate\n");
    }
    
    return result;
}

int handle_cert_command(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s cert <subcommand>\n", argv[0]);
        printf("\nSubcommands:\n");
        printf("  status                           Show certificate status with validity info\n");
        printf("  set <domain> <cert> <key>       Set SSL certificate and key paths for a site\n");
        printf("  generate [domain] [-d days]     Generate self-signed certificate\n");
        printf("                                    (default: 365 days, max: 3650 days)\n");
        printf("  issue <domain>                   Issue Let's Encrypt certificate (90 days)\n");
        printf("  renew                            Renew Let's Encrypt certificates\n");
        printf("  list                             List all installed certificates\n");
        printf("  auto                             Auto-configure SSL certificates for all sites\n");
        printf("  test <domain>                    Test certificate configuration for a site\n");
        printf("  install-cron                     Install auto-renewal cron job\n");
        printf("  dry-run                          Test certificate renewal without making changes\n");
        printf("  revoke <domain>                  Revoke and delete Let's Encrypt certificate\n");
        printf("\nLet's Encrypt Info:\n");
        printf("  - Certificate validity: 90 days (fixed by Let's Encrypt)\n");
        printf("  - Auto-renewal recommended when < 30 days remaining\n");
        printf("  - Use 'waf cert install-cron' to enable auto-renewal\n");
        return 1;
    }
    
    const char *subcmd = argv[2];
    
    if (strcmp(subcmd, "status") == 0) {
        return cert_status();
    }
    
    if (strcmp(subcmd, "set") == 0) {
        if (argc < 6) {
            fprintf(stderr, "Please specify domain, certificate and key paths\n");
            return 1;
        }
        return cert_set(argv[3], argv[4], argv[5]);
    }
    
    if (strcmp(subcmd, "generate") == 0) {
        int days = 365;
        const char *domain = NULL;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
                days = atoi(argv[++i]);
                if (days <= 0) days = 365;
            } else if (!domain && strncmp(argv[i], "-", 1) != 0) {
                domain = argv[i];
            }
        }
        return cert_generate(domain, days);
    }
    
    if (strcmp(subcmd, "issue") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Please specify domain\n");
            return 1;
        }
        
        const char *domain = argv[3];
        return cert_issue(domain);
    }
    
    if (strcmp(subcmd, "renew") == 0) {
        return cert_renew();
    }
    
    if (strcmp(subcmd, "list") == 0) {
        return cert_list();
    }
    
    if (strcmp(subcmd, "auto") == 0) {
        return cert_auto();
    }
    
    if (strcmp(subcmd, "test") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Please specify domain\n");
            return 1;
        }
        return cert_test(argv[3]);
    }
    
    if (strcmp(subcmd, "install-cron") == 0) {
        return cert_install_cron();
    }
    
    if (strcmp(subcmd, "dry-run") == 0) {
        return cert_dry_run();
    }
    
    if (strcmp(subcmd, "revoke") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Please specify domain\n");
            return 1;
        }
        return cert_revoke(argv[3]);
    }
    
    fprintf(stderr, "Unknown cert subcommand: %s\n", subcmd);
    fprintf(stderr, "Use 'waf cert help' for usage information\n");
    return 1;
}

#include "../include/waf_ai.h"
#include "../include/waf_ai_cnn.h"
#include "../include/waf_ai_ae.h"
#include "../include/waf_ai_guard.h"
#include "../include/waf_rules.h"
#include "../include/waf_log.h"
#include "../include/waf_http.h"
#include <math.h>

/* v3.0 模型目录（ai_config.model_path 同目录），写入 out 缓冲 */
static void ai_model_dir(const ai_config_t *cfg, char *out, size_t outsz) {
    snprintf(out, outsz, "%s", cfg->model_path);
    char *slash = strrchr(out, '/');
    if (slash) *slash = '\0';
    else snprintf(out, outsz, ".");
}

/* calibrate/eval 需要 CNN/AE 在内存中；ai_fusion.dat 缺失时 ai_init 的
 * fusion_load 会放弃加载，这里独立补齐（只加载 CNN/AE，不要求 fusion 校准文件） */
static void ai_cli_ensure_models(ai_config_t *cfg) {
    char dir[512], p[600];
    ai_model_dir(cfg, dir, sizeof(dir));
    if (!cfg->cnn_model) {
        snprintf(p, sizeof(p), "%s/ai_cnn.dat", dir);
        cfg->cnn_model = ai_cnn_load(p);
    }
    if (!cfg->ae_model) {
        snprintf(p, sizeof(p), "%s/ai_ae.dat", dir);
        cfg->ae_model = ai_ae_load(p);
    }
}

/* 特征名（用于 probe / 权重诊断输出） */
static const char *ai_feat_name(int i) {
    static const char *srcn[7] = {"url","urldec","query","querydec","body","bodydec","hdrs"};
    static const char *fn[8] = {"len","ent","enc","spc","sql","xss","cmd","path"};
    static const char *xn[8] = {"ANY_SQL","ANY_XSS","ANY_CMD","ANY_PATH","ANY_OTHER","FAMILIES","TOT_ENC","EXTRA"};
    static char buf[32];
    if (i < 0 || i >= AI_FEAT_DIM) return "?";
    if (i < 56) { snprintf(buf, sizeof(buf), "%s.%s", srcn[i / 8], fn[i % 8]); return buf; }
    return xn[i - 56];
}

int handle_ai_command(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s ai <subcommand>\n", argv[0]);
        printf("\nSubcommands:\n");
        printf("  status    Show AI model status\n");
        printf("  train     Train AI model from logs\n");
        printf("  distill   Offline distillation from labeled corpus (black/white lists)\n");
        printf("  eval      Evaluate CNN/AE/fusion on corpus\n");
        printf("  probe     Print AI features and score for one raw request file\n");
        printf("  rules     List AI-learned rules\n");
        printf("  rollback  Rollback AI-learned rules to previous snapshot\n");
        printf("  train-cnn Train char-CNN channel (--black --white [--epochs N] [--lr X] [--gradcheck])\n");
        printf("  train-ae  Train autoencoder channel (--white [--epochs N] [--lr X])\n");
        printf("  calibrate Calibrate fusion weights+threshold (--black --white [--out path])\n");
        return 1;
    }
    
    const char *subcmd = argv[2];
    
    log_init("logs");
    
    waf_config_t waf_config;
    memset(&waf_config, 0, sizeof(waf_config));
    load_waf_config(&waf_config);
    
    ai_config_t *ai_config = (ai_config_t*)malloc(sizeof(ai_config_t));
    if (!ai_config) {
        fprintf(stderr, "Failed to allocate memory for AI config\n");
        return 1;
    }
    ai_init(ai_config, &waf_config);
    
    if (strcmp(subcmd, "status") == 0) {
        ai_ensemble_status_t ensemble_status;
        ai_get_ensemble_status(ai_config, &ensemble_status);
        
        printf("AI Ensemble Status:\n");
        printf("===================\n\n");
        printf("Ensemble Type:     %s\n", ensemble_status.ensemble_type);
        printf("Model Count:       %d\n", ensemble_status.model_count);
        printf("Ensemble Threshold: %.4f\n", ensemble_status.ensemble_threshold);
        printf("\nModels:\n");
        for (int i = 0; i < ensemble_status.model_count; i++) {
            printf("  [%d] %s - %s\n", i, ensemble_status.model_type[i], 
                   ensemble_status.trained[i] ? "Trained" : "Untrained");
        }
        printf("\n");
        
        ai_model_status_t status;
        ai_get_model_status(ai_config, &status);
        
        printf("Primary Model Status:\n");
        printf("=====================\n\n");
        printf("Model Type:        %s\n", status.model_type);
        printf("Trained:           %s\n", status.trained ? "Yes" : "No");
        printf("Sample Count:      %d\n", status.sample_count);
        printf("Feature Count:     %d\n", status.feature_count);
        printf("Detection Threshold: %.4f\n", status.threshold);
        printf("Detection Count:   %d\n", status.detection_count);
        printf("Auto Learning:     %s\n", status.auto_learning_enabled ? "Enabled" : "Disabled");
        printf("\n");

        /* v3.0 双通道状态 */
        ai_cli_ensure_models(ai_config);
        printf("Dual-Channel (v3.0):\n");
        printf("====================\n\n");
        printf("  char-CNN:   %s\n", (ai_config->cnn_model && ai_cnn_is_trained((const ai_cnn_t *)ai_config->cnn_model)) ? "Trained" : "Not loaded");
        printf("  Autoencoder:%s\n", (ai_config->ae_model && ai_ae_is_trained((const ai_ae_t *)ai_config->ae_model)) ? " Trained" : " Not loaded");
        printf("  Fusion:     %s", ai_config->fusion_ready ? "ready" : "not ready");
        if (ai_config->fusion_ready) {
            printf("  (w_cnn=%.3f w_ae=%.3f thr=%.4f)",
                   ai_config->fusion_w_cnn, ai_config->fusion_w_ae, ai_config->fusion_threshold);
        }
        printf("\n\n");

        free(ai_config);
        return 0;
    } else if (strcmp(subcmd, "train") == 0) {
        const char *log_dir = "logs";
        if (argc >= 4) {
            log_dir = argv[3];
        }
        
        printf("Training AI model from logs...\n");
        printf("==============================\n\n");
        printf("Log directory: %s\n", log_dir);
        printf("Training mode: Supervised learning\n");
        printf("---------------------------------\n\n");
        
        int count = ai_train_from_logs(ai_config, log_dir);
        
        if (count >= 0) {
            printf("✅ Training completed!\n");
            printf("   Samples processed: %d\n", count);
            
            ai_model_status_t status;
            ai_get_model_status(ai_config, &status);
            
            printf("\nUpdated Model Status:\n");
            printf("   Trained:           %s\n", status.trained ? "Yes" : "No");
            printf("   Sample Count:      %d\n", status.sample_count);
            printf("   Feature Count:     %d\n", status.feature_count);
        } else {
            printf("❌ Training failed!\n");
            free(ai_config);
            return 1;
        }
        
        free(ai_config);
        return 0;
    } else if (strcmp(subcmd, "train-cnn") == 0) {
        const char *black = "/tmp/black_all.txt";
        const char *white = "/tmp/white_all.txt";
        int epochs = 20, gradcheck = 0;
        double lr = 1e-3;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--black") == 0 && i + 1 < argc) black = argv[++i];
            else if (strcmp(argv[i], "--white") == 0 && i + 1 < argc) white = argv[++i];
            else if (strcmp(argv[i], "--epochs") == 0 && i + 1 < argc) epochs = atoi(argv[++i]);
            else if (strcmp(argv[i], "--lr") == 0 && i + 1 < argc) lr = atof(argv[++i]);
            else if (strcmp(argv[i], "--gradcheck") == 0) gradcheck = 1;
        }
        printf("char-CNN training (supervised, ground-truth labels)\n");
        printf("===================================================\n");
        printf("black list : %s\nwhite list : %s\nepochs=%d lr=%g gradcheck=%d\n\n",
               black, white, epochs, lr, gradcheck);

        ai_cnn_t *cnn = ai_cnn_create();
        if (!cnn) { printf("CNN create failed\n"); free(ai_config); return 1; }
        int rc = ai_cnn_train(cnn, black, white, epochs, lr, gradcheck);
        if (rc != 0) {
            printf("CNN training FAILED (rc=%d)\n", rc);
            ai_cnn_destroy(cnn);
            free(ai_config);
            return 1;
        }
        char dir[512], p[600];
        ai_model_dir(ai_config, dir, sizeof(dir));
        snprintf(p, sizeof(p), "%s/ai_cnn.dat", dir);
        if (ai_cnn_save(cnn, p) == 0)
            printf("CNN model saved: %s\n", p);
        else
            printf("CNN save FAILED: %s\n", p);
        ai_cnn_destroy(cnn);
        free(ai_config);
        return 0;
    } else if (strcmp(subcmd, "train-ae") == 0) {
        const char *white = "/tmp/white_all.txt";
        int epochs = 30;
        double lr = 1e-3;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--white") == 0 && i + 1 < argc) white = argv[++i];
            else if (strcmp(argv[i], "--epochs") == 0 && i + 1 < argc) epochs = atoi(argv[++i]);
            else if (strcmp(argv[i], "--lr") == 0 && i + 1 < argc) lr = atof(argv[++i]);
        }
        printf("Autoencoder training (self-supervised, white traffic only)\n");
        printf("==========================================================\n");
        printf("white list : %s\nepochs=%d lr=%g\n\n", white, epochs, lr);

        ai_ae_t *ae = ai_ae_create();
        if (!ae) { printf("AE create failed\n"); free(ai_config); return 1; }
        int rc = ai_ae_train(ae, white, epochs, lr);
        if (rc != 0) {
            printf("AE training FAILED (rc=%d)\n", rc);
            ai_ae_destroy(ae);
            free(ai_config);
            return 1;
        }
        char dir[512], p[600];
        ai_model_dir(ai_config, dir, sizeof(dir));
        snprintf(p, sizeof(p), "%s/ai_ae.dat", dir);
        if (ai_ae_save(ae, p) == 0)
            printf("AE model saved: %s\n", p);
        else
            printf("AE save FAILED: %s\n", p);
        ai_ae_destroy(ae);
        free(ai_config);
        return 0;
    } else if (strcmp(subcmd, "calibrate") == 0) {
        const char *black = "/tmp/black_all.txt";
        const char *white = "/tmp/white_all.txt";
        const char *out = NULL;
        char outbuf[600];
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--black") == 0 && i + 1 < argc) black = argv[++i];
            else if (strcmp(argv[i], "--white") == 0 && i + 1 < argc) white = argv[++i];
            else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) out = argv[++i];
        }
        if (!out) {
            char dir[512];
            ai_model_dir(ai_config, dir, sizeof(dir));
            snprintf(outbuf, sizeof(outbuf), "%s/ai_fusion.dat", dir);
            out = outbuf;
        }
        ai_cli_ensure_models(ai_config);
        if (!ai_config->cnn_model || !ai_cnn_is_trained((const ai_cnn_t *)ai_config->cnn_model)) {
            printf("Calibrate FAILED: no trained CNN model (run 'ai train-cnn' first)\n");
            free(ai_config);
            return 1;
        }
        printf("Fusion calibration\n");
        printf("==================\n");
        printf("black list : %s\nwhite list : %s\nout : %s\n\n", black, white, out);
        if (ai_calibrate_fusion(ai_config, black, white, out) == 0) {
            printf("Fusion calibration saved: %s\n", out);
            free(ai_config);
            return 0;
        }
        printf("Fusion calibration FAILED\n");
        free(ai_config);
        return 1;
    } else if (strcmp(subcmd, "distill") == 0) {
        const char *black = "/tmp/black_all.txt";
        const char *white = "/tmp/white_all.txt";
        const char *out = NULL;
        int epochs = 400;
        double lr = 0.5;
        for (int i = 3; i + 1 < argc; i++) {
            if (strcmp(argv[i], "--black") == 0) black = argv[++i];
            else if (strcmp(argv[i], "--white") == 0) white = argv[++i];
            else if (strcmp(argv[i], "--out") == 0) out = argv[++i];
            else if (strcmp(argv[i], "--epochs") == 0) epochs = atoi(argv[++i]);
            else if (strcmp(argv[i], "--lr") == 0) lr = atof(argv[++i]);
        }
        printf("Offline distillation (rule-distilled logistic model)\n");
        printf("====================================================\n");
        printf("black list : %s\nwhite list : %s\nepochs=%d lr=%.3f\n\n", black, white, epochs, lr);

        ai_train_report_t rep;
        if (ai_distill_train(ai_config, black, white, out, &ai_config->guard, epochs, lr, &rep) == 0) {
            printf("Distillation OK\n");
            printf("  black files/sampled : %ld / %ld\n", rep.black_files, rep.black_sampled);
            printf("  white files/sampled : %ld / %ld\n", rep.white_files, rep.white_sampled);
            printf("  parse failures      : %ld\n", rep.parse_fail);
            printf("  calibrated threshold: %.2f\n", rep.best_threshold);
            printf("  train-set  FN(黑漏) : %ld   FP(白误) : %ld  (err=%ld)\n",
                   rep.pos_below_thr, rep.neg_above_thr, rep.pos_below_thr + rep.neg_above_thr);
            printf("  score: black mean=%.3f min=%.3f | white mean=%.3f max=%.3f\n",
                   rep.pos_mean, rep.pos_min, rep.neg_mean, rep.neg_max);
            ai_model_t *m0 = &ai_config->models[0];
            if (m0->trained) {
                int used[AI_FEAT_DIM];
                memset(used, 0, sizeof(used));
                printf("  top features by |weight| (bias=%.3f):\n", m0->bias);
                for (int r = 0; r < 12; r++) {
                    int best = -1;
                    double bv = -1.0;
                    for (int i = 0; i < AI_FEAT_DIM; i++) {
                        if (used[i]) continue;
                        double av = fabs(m0->weights[i]);
                        if (av > bv) { bv = av; best = i; }
                    }
                    if (best < 0 || bv <= 0.0) break;
                    used[best] = 1;
                    printf("    %-12s  w=%+.3f  mean=%.3f std=%.3f\n",
                           ai_feat_name(best), m0->weights[best], m0->mean[best], m0->std[best]);
                }
            }
            free(ai_config);
            return 0;
        }
        printf("Distillation FAILED\n");
        free(ai_config);
        return 1;
    } else if (strcmp(subcmd, "eval") == 0) {
        const char *black = "/tmp/black_all.txt";
        const char *white = "/tmp/white_all.txt";
        for (int i = 3; i + 1 < argc; i++) {
            if (strcmp(argv[i], "--black") == 0) black = argv[++i];
            else if (strcmp(argv[i], "--white") == 0) white = argv[++i];
        }
        ai_cli_ensure_models(ai_config);
        int have_cnn = ai_config->cnn_model && ai_cnn_is_trained((const ai_cnn_t *)ai_config->cnn_model);
        int have_ae  = ai_config->ae_model && ai_ae_is_trained((const ai_ae_t *)ai_config->ae_model);
        if (!have_cnn && !have_ae) {
            printf("Eval failed (no trained CNN/AE model)\n");
            free(ai_config);
            return 1;
        }
        /* 三链路报告：CNN-only / AE-only / fusion（auto 级联全链路经 blazehttp 回放验收） */
        long fn_c = 0, fp_c = 0, fn_a = 0, fp_a = 0, fn_f = 0, fp_f = 0, bt = 0, wt = 0;
        static char raw[MAX_REQUEST_SIZE];
        char line[1024];
        double thr_c = 0.5, thr_a = 0.5;
        double thr_f = ai_config->fusion_ready ? ai_config->fusion_threshold : 0.98;
        for (int pass = 0; pass < 2; pass++) {
            const char *list = pass == 0 ? black : white;
            int label = pass == 0 ? 1 : 0;
            FILE *fp = fopen(list, "r");
            if (!fp) continue;
            while (fgets(line, sizeof(line), fp)) {
                size_t ll = strlen(line);
                while (ll > 0 && (line[ll-1] == '\n' || line[ll-1] == '\r')) line[--ll] = '\0';
                if (ll == 0) continue;
                FILE *rf = fopen(line, "rb");
                if (!rf) continue;
                size_t rd = fread(raw, 1, sizeof(raw) - 1, rf);
                fclose(rf);
                raw[rd] = '\0';
                http_request_t rq;
                memset(&rq, 0, sizeof(rq));
                if (http_parse_request(raw, rd, &rq) != 0) continue;
                double sc = have_cnn ? ai_cnn_score((const ai_cnn_t *)ai_config->cnn_model, &rq) : 0.0;
                double sa = have_ae ? ai_ae_score((const ai_ae_t *)ai_config->ae_model, &rq) : 0.0;
                double sf = ai_config->fusion_w_cnn * sc + ai_config->fusion_w_ae * sa;
                if (label) {
                    bt++;
                    if (have_cnn && sc < thr_c) fn_c++;
                    if (have_ae && sa < thr_a) fn_a++;
                    if (ai_config->fusion_ready && sf < thr_f) fn_f++;
                } else {
                    wt++;
                    if (have_cnn && sc >= thr_c) fp_c++;
                    if (have_ae && sa >= thr_a) fp_a++;
                    if (ai_config->fusion_ready && sf >= thr_f) fp_f++;
                }
                if (((bt + wt) % 5000) == 0) { printf("  eval %ld...\r", bt + wt); fflush(stdout); }
            }
            fclose(fp);
        }
        printf("\nEval (black=%ld white=%ld)\n", bt, wt);
        if (have_cnn)
            printf("  CNN-only  @%.2f : FN=%ld FP=%ld  err=%ld\n", thr_c, fn_c, fp_c, fn_c + fp_c);
        if (have_ae)
            printf("  AE-only   @%.2f : FN=%ld FP=%ld  err=%ld\n", thr_a, fn_a, fp_a, fn_a + fp_a);
        if (ai_config->fusion_ready)
            printf("  Fusion    @%.4f (w_cnn=%.2f w_ae=%.2f): FN=%ld FP=%ld  err=%ld  acc=%.4f%%\n",
                   thr_f, ai_config->fusion_w_cnn, ai_config->fusion_w_ae, fn_f, fp_f,
                   fn_f + fp_f,
                   (bt + wt) > 0 ? 100.0 * (double)(bt + wt - fn_f - fp_f) / (double)(bt + wt) : 0.0);
        free(ai_config);
        return 0;
    } else if (strcmp(subcmd, "probe") == 0) {
        if (argc < 4) {
            printf("Usage: %s ai probe <raw_http_request_file>\n", argv[0]);
            free(ai_config);
            return 1;
        }
        FILE *pf = fopen(argv[3], "rb");
        if (!pf) { printf("Cannot open %s\n", argv[3]); free(ai_config); return 1; }
        static char praw[262144];
        size_t prn = fread(praw, 1, sizeof(praw) - 1, pf);
        fclose(pf);
        praw[prn] = '\0';
        http_request_t rq;
        memset(&rq, 0, sizeof(rq));
        if (http_parse_request(praw, prn, &rq) != 0) {
            printf("Parse failed\n");
            free(ai_config);
            return 1;
        }
        double feats[AI_FEAT_DIM];
        int fc = 0;
        ai_extract_features(&rq, feats, &fc);
        double score = ai_score_request(ai_config, &rq);
        printf("AI probe: %s\n", argv[3]);
        printf("  method=%s url=%s\n", rq.method, rq.url);
        printf("  score=%.4f  thr=%.4f  verdict=%s\n", score, ai_config->ensemble_threshold,
               score >= ai_config->ensemble_threshold ? "MALICIOUS" : "normal");
        printf("  non-zero features:\n");
        for (int i = 0; i < fc; i++) {
            if (feats[i] != 0.0)
                printf("    [%2d] %-12s = %.5g\n", i, ai_feat_name(i), feats[i]);
        }
        free(ai_config);
        return 0;
    } else if (strcmp(subcmd, "rules") == 0) {
        const char *path = ai_config->guard.learned_rules_path;
        printf("AI-learned rules: %s\n", path);
        FILE *rf = fopen(path, "r");
        if (!rf) { printf("  (none)\n"); free(ai_config); return 0; }
        char rl[1024]; int n = 0;
        while (fgets(rl, sizeof(rl), rf)) { printf("  %s", rl); n++; }
        fclose(rf);
        printf("  total: %d rules\n", n);
        free(ai_config);
        return 0;
    } else if (strcmp(subcmd, "rollback") == 0) {
        if (ai_guard_rollback(ai_config) == 0) {
            /* CLI 内的 rules_reload() 只作用于本进程；须向运行中的守护进程发
             * SIGHUP（其 signal_handler 会调用 rules_reload），否则回滚不生效 */
            pid_t dpid;
            if (read_pid_file(&dpid) == 0 && dpid > 0 && kill(dpid, SIGHUP) == 0)
                printf("Rolled back AI-learned rules; signalled daemon (pid %d) to reload\n", dpid);
            else
                printf("Rolled back AI-learned rules to previous snapshot (daemon not signalled)\n");
            free(ai_config);
            return 0;
        }
        printf("Rollback failed (no .bak snapshot?)\n");
        free(ai_config);
        return 1;
    }

    free(ai_config);
    fprintf(stderr, "Unknown ai subcommand: %s\n", subcmd);
    return 1;
}

// External bypass module functions
extern int bypass_init(const char *config_dir);
extern int bypass_start(void);
extern void bypass_stop(void);
extern void bypass_status(void);
extern int bypass_reload(const char *config_dir);

int handle_bypass_command(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s bypass <subcommand>\n", argv[0]);
        printf("\nSubcommands:\n");
        printf("  start           Start bypass servers for all configured sites\n");
        printf("  stop            Stop all bypass servers\n");
        printf("  status          Show bypass server status\n");
        printf("  reload          Reload bypass configuration\n");
        printf("\nNote: Bypass servers handle sites with backend_port=0\n");
        printf("      These sites are NOT protected by WAF defense.\n");
        return 1;
    }
    
    const char *subcmd = argv[2];
    
    if (strcmp(subcmd, "start") == 0) {
        printf("Starting bypass servers...\n");
        if (bypass_init("/opt/waf/config/sites-bypass") < 0) {
            fprintf(stderr, "Failed to initialize bypass module\n");
            return 1;
        }
        return bypass_start();
    }
    else if (strcmp(subcmd, "stop") == 0) {
        printf("Stopping bypass servers...\n");
        bypass_stop();
        return 0;
    }
    else if (strcmp(subcmd, "status") == 0) {
        bypass_status();
        return 0;
    }
    else if (strcmp(subcmd, "reload") == 0) {
        printf("Reloading bypass configuration...\n");
        bypass_reload("/opt/waf/config/sites-bypass");
        return 0;
    }
    
    fprintf(stderr, "Unknown bypass subcommand: %s\n", subcmd);
    return 1;
}

// External webadmin module functions
extern int webadmin_init(void);
extern int webadmin_start(void);
extern void webadmin_stop(void);
extern void webadmin_status(void);
extern int webadmin_restart(void);
extern void webadmin_config(void);

int handle_webadmin_command(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s webadmin <subcommand>\n", argv[0]);
        printf("\nSubcommands:\n");
        printf("  start           Start WebAdmin server (HTTP/HTTPS)\n");
        printf("  stop            Stop WebAdmin server\n");
        printf("  restart         Restart WebAdmin server\n");
        printf("  status          Show WebAdmin server status\n");
        printf("  config          Show WebAdmin configuration\n");
        printf("\nWebAdmin provides the WAF management interface at demo.local\n");
        printf("This service does NOT go through WAF defense.\n");
        printf("\nPorts:\n");
        printf("  HTTP:  8080\n");
        printf("  HTTPS: 28443\n");
        return 1;
    }
    
    const char *subcmd = argv[2];
    
    if (strcmp(subcmd, "start") == 0) {
        printf("Starting WebAdmin server...\n");
        webadmin_init();
        return webadmin_start();
    }
    else if (strcmp(subcmd, "stop") == 0) {
        printf("Stopping WebAdmin server...\n");
        webadmin_stop();
        return 0;
    }
    else if (strcmp(subcmd, "restart") == 0) {
        printf("Restarting WebAdmin server...\n");
        webadmin_restart();
        return 0;
    }
    else if (strcmp(subcmd, "status") == 0) {
        webadmin_status();
        return 0;
    }
    else if (strcmp(subcmd, "config") == 0) {
        webadmin_init();
        webadmin_config();
        return 0;
    }
    
    fprintf(stderr, "Unknown webadmin subcommand: %s\n", subcmd);
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *command = argv[1];
    
    if (strcmp(command, "help") == 0 || strcmp(command, "-h") == 0 || strcmp(command, "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }
    
    if (strcmp(command, "-v") == 0 || strcmp(command, "--version") == 0) {
        print_version();
        return 0;
    }
    
    if (strcmp(command, "stop") == 0) {
        return stop_waf();
    }
    
    if (strcmp(command, "status") == 0) {
        return status_waf();
    }
    
    if (strcmp(command, "sites") == 0) {
        return show_sites();
    }
    
    if (strcmp(command, "check") == 0 || strcmp(command, "-t") == 0) {
        return check_config();
    }
    
    if (strcmp(command, "backend") == 0) {
        return handle_backend_command(argc, argv);
    }
    
    if (strcmp(command, "cert") == 0) {
        return handle_cert_command(argc, argv);
    }

    if (strcmp(command, "bypass") == 0) {
        return handle_bypass_command(argc, argv);
    }

    if (strcmp(command, "webadmin") == 0) {
        return handle_webadmin_command(argc, argv);
    }

    if (strcmp(command, "ai") == 0) {
        return handle_ai_command(argc, argv);
    }

    if (strcmp(command, "restart") == 0) {
        stop_waf();
        sleep(1);
        waf_config_t config = {0};
        config.http_port = WAF_DEFAULT_HTTP_PORT;
        config.https_port = WAF_DEFAULT_HTTPS_PORT;
        config.backend_port = WAF_DEFAULT_BACKEND_PORT;
        config.ssl_enabled = 0;
        config.mode = WAF_MODE_BLOCKING;
        strcpy(config.backend_host, WAF_DEFAULT_BACKEND_HOST);
        strcpy(config.log_dir, "logs");
        strcpy(config.rules_dir, "rules");
        config.log_rotate_size_mb = WAF_DEFAULT_LOG_ROTATE_MB;
        config.log_retention_days = WAF_DEFAULT_LOG_RETENTION;

        load_waf_config(&config);
        if (config.cert_file[0]) {
            config.ssl_enabled = 1;
        }
        
        return run_waf(&config, 1);
    }
    
    if (strcmp(command, "start") != 0) {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(argv[0]);
        return 1;
    }
    
    waf_config_t config = {0};
    config.http_port = WAF_DEFAULT_HTTP_PORT;
    config.https_port = WAF_DEFAULT_HTTPS_PORT;
    config.backend_port = WAF_DEFAULT_BACKEND_PORT;
    config.worker_threads = WAF_WORKER_THREADS;
    config.mode = WAF_MODE_BLOCKING;
    config.detection_mode = WAF_DEFAULT_DETECTION_MODE;
    config.enable_cc_protection = 1;
    config.enable_api_protection = 1;
    config.ssl_enabled = 0;
    config.max_body_size = MAX_BODY_SIZE;
    strcpy(config.backend_host, WAF_DEFAULT_BACKEND_HOST);
    strcpy(config.log_dir, "logs");
    strcpy(config.rules_dir, "rules");
    config.log_rotate_size_mb = WAF_DEFAULT_LOG_ROTATE_MB;
    config.log_retention_days = WAF_DEFAULT_LOG_RETENTION;
    
    load_waf_config(&config);
    if (config.cert_file[0]) {
        config.ssl_enabled = 1;
    }
    
    int daemonize = 0;
    
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            config.http_port = atoi(argv[++i]);
            /* 标记 CLI 显式指定：sites.conf [global] 不得覆盖（发行包自定义端口测试依赖） */
            setenv("WAF_HTTP_PORT", argv[i], 1);
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            config.https_port = atoi(argv[++i]);
            setenv("WAF_HTTPS_PORT", argv[i], 1);
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            char *colon = strchr(argv[++i], ':');
            if (colon) {
                *colon = '\0';
                strncpy(config.backend_host, argv[i], sizeof(config.backend_host) - 1);
                config.backend_port = atoi(colon + 1);
            } else {
                strncpy(config.backend_host, argv[i], sizeof(config.backend_host) - 1);
            }
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "learning") == 0) {
                config.mode = WAF_MODE_LEARNING;
            } else if (strcmp(argv[i], "detection") == 0) {
                config.mode = WAF_MODE_DETECTION;
            } else if (strcmp(argv[i], "blocking") == 0) {
                config.mode = WAF_MODE_BLOCKING;
            } else {
                fprintf(stderr, "Invalid mode: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            config.worker_threads = atoi(argv[++i]);
            setenv("WAF_WORKER_THREADS", argv[i], 1);
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            strncpy(config.log_dir, argv[++i], sizeof(config.log_dir) - 1);
        } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            strncpy(config.rules_dir, argv[++i], sizeof(config.rules_dir) - 1);
        } else if (strcmp(argv[i], "--no-cc") == 0) {
            config.enable_cc_protection = 0;
        } else if (strcmp(argv[i], "--no-api") == 0) {
            config.enable_api_protection = 0;
        } else if (strcmp(argv[i], "--daemon") == 0) {
            daemonize = 1;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    if (config.cert_file[0]) {
        config.ssl_enabled = 1;
    }
    return run_waf(&config, daemonize);
}
