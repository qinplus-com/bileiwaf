#include "../include/waf_log.h"
#include <stdarg.h>
#include <dirent.h>
#include <sys/stat.h>

static const char *attack_type_names[] = {
    "SQL_INJECTION", "XSS", "CMD_INJECTION", "PATH_TRAVERSAL",
    "FILE_UPLOAD", "CSRF", "LDAP_INJECTION", "XML_INJECTION",
    "JSON_INJECTION", "SSRF", "DESERIALIZATION", "SCANNER",
    "CC", "MALICIOUS_BOT", "BRUTE_FORCE", "API_ABUSE", "UNKNOWN"
};

#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO  1
#define LOG_LEVEL_WARN  2
#define LOG_LEVEL_ERROR 3
#define LOG_LEVEL_FATAL 4

static char log_directory[512] = "logs";
static FILE *attack_log_fp = NULL;
static FILE *access_log_fp = NULL;
static FILE *error_log_fp = NULL;
static FILE *audit_log_fp = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static int log_level = LOG_LEVEL_INFO;

/* ---- 日志轮转/保留期（waf.conf: log_rotate_size / log_retention_days）----
 * 轮转：单文件超过阈值 → 关闭并重命名为 waf-xxx.log.YYYYmmdd-HHMMSS，再重新打开；
 * 清理：每 24 小时扫描一次 log_dir，删除超过保留期的轮转归档（只动 .log.* 归档，
 * 不碰正在写的当前日志，也不碰 site 日志等其它文件）。 */
static long      rotate_size_bytes = 0;   /* 0 = 关闭按大小轮转 */
static int       retention_days    = 0;   /* 0 = 归档永久保留 */
static time_t    last_cleanup      = 0;
static int       in_rotate         = 0;   /* 防重入：轮转过程不再写日志 */
static unsigned  writes_since_check = 0;  /* 每 N 次写入做一次体积检查，摊薄 stat 开销 */

void log_set_rotation(int size_mb, int retention) {
    rotate_size_bytes = (size_mb > 0) ? (long)size_mb * 1024L * 1024L : 0;
    retention_days    = (retention > 0) ? retention : 0;
    last_cleanup      = 0;   /* 首次写入时立即执行一次保留期清理 */
}

/* 关闭并归档单个日志，再以追加模式重开（调用方须持有 log_mutex） */
static void rotate_one_locked(FILE **fp, const char *name, const char *ts) {
    if (!*fp) return;
    char cur[1024], arc[1024];
    snprintf(cur, sizeof(cur), "%s/%s", log_directory, name);
    if (ftell(*fp) <= 0) return;   /* 空文件不轮转 */

    fclose(*fp);
    *fp = NULL;

    /* 同一秒内重复轮转时加序号，避免覆盖已有归档 */
    snprintf(arc, sizeof(arc), "%s.%s", cur, ts);
    for (int i = 1; i < 100; i++) {
        struct stat st;
        if (stat(arc, &st) != 0) break;
        snprintf(arc, sizeof(arc), "%s.%s.%d", cur, ts, i);
    }
    if (rename(cur, arc) != 0) {
        fprintf(stderr, "[log] 轮转失败 %s: %s\n", cur, strerror(errno));
    } else {
        fprintf(stderr, "[log] 已轮转 %s -> %s\n", cur, arc);
    }
    *fp = fopen(cur, "a");
}

/* 删除超过保留期的轮转归档（调用方须持有 log_mutex） */
static void cleanup_locked(void) {
    DIR *d = opendir(log_directory);
    if (!d) return;
    time_t cutoff = time(NULL) - (time_t)retention_days * 86400;
    struct dirent *e;
    int removed = 0;
    while ((e = readdir(d)) != NULL) {
        /* 仅匹配本 WAF 的轮转归档：waf-*.log.<时间戳>[.<序号>] */
        if (strncmp(e->d_name, "waf-", 4) != 0) continue;
        if (!strstr(e->d_name, ".log.")) continue;
        char p[1200];
        snprintf(p, sizeof(p), "%s/%s", log_directory, e->d_name);
        struct stat st;
        if (stat(p, &st) == 0 && S_ISREG(st.st_mode) && st.st_mtime < cutoff) {
            if (unlink(p) == 0) removed++;
        }
    }
    closedir(d);
    fprintf(stderr, "[log] 保留期清理：删除 %d 个超过 %d 天的归档\n", removed, retention_days);
}

/* 写日志后调用：按体积轮转 + 到期清理（调用方须持有 log_mutex） */
static void maintain_locked(void) {
    if (in_rotate) return;
    in_rotate = 1;

    time_t now = time(NULL);
    /* 体积检查每 64 次写入做一次，避免高频请求下每次都 ftell */
    if (rotate_size_bytes > 0 && ++writes_since_check >= 64) {
        writes_since_check = 0;
        char ts[32];
        struct tm tm_now;
        localtime_r(&now, &tm_now);
        strftime(ts, sizeof(ts), "%Y%m%d-%H%M%S", &tm_now);
        if (attack_log_fp && ftell(attack_log_fp) >= rotate_size_bytes)
            rotate_one_locked(&attack_log_fp, "waf-attack.log", ts);
        if (access_log_fp && ftell(access_log_fp) >= rotate_size_bytes)
            rotate_one_locked(&access_log_fp, "waf-access.log", ts);
        if (error_log_fp && ftell(error_log_fp) >= rotate_size_bytes)
            rotate_one_locked(&error_log_fp, "waf-error.log", ts);
        if (audit_log_fp && ftell(audit_log_fp) >= rotate_size_bytes)
            rotate_one_locked(&audit_log_fp, "waf-audit.log", ts);
    }

    /* 保留期清理每 24 小时一次 */
    if (retention_days > 0 && (last_cleanup == 0 || now - last_cleanup >= 86400)) {
        cleanup_locked();
        last_cleanup = now;
    }

    in_rotate = 0;
}

int log_init(const char *log_dir) {
    if (log_dir) {
        strncpy(log_directory, log_dir, sizeof(log_directory) - 1);
    }
    
    mkdir(log_directory, 0755);
    
    char path[1024];
    
    snprintf(path, sizeof(path), "%s/waf-attack.log", log_directory);
    attack_log_fp = fopen(path, "a");
    if (!attack_log_fp) {
        fprintf(stderr, "Failed to open attack log: %s (%s)\n", path, strerror(errno));
    }
    
    snprintf(path, sizeof(path), "%s/waf-access.log", log_directory);
    access_log_fp = fopen(path, "a");
    if (!access_log_fp) {
        fprintf(stderr, "Failed to open access log: %s (%s)\n", path, strerror(errno));
    }
    
    snprintf(path, sizeof(path), "%s/waf-error.log", log_directory);
    error_log_fp = fopen(path, "a");
    if (!error_log_fp) {
        fprintf(stderr, "Failed to open error log: %s (%s)\n", path, strerror(errno));
    }
    
    snprintf(path, sizeof(path), "%s/waf-audit.log", log_directory);
    audit_log_fp = fopen(path, "a");
    if (!audit_log_fp) {
        fprintf(stderr, "Failed to open audit log: %s (%s)\n", path, strerror(errno));
    }
    
    fprintf(stderr, "Log directory: %s\n", log_directory);
    fprintf(stderr, "Attack log FP: %p\n", attack_log_fp);
    fprintf(stderr, "Access log FP: %p\n", access_log_fp);
    
    return 0;
}

void log_destroy(void) {
    pthread_mutex_lock(&log_mutex);
    
    if (attack_log_fp) {
        fclose(attack_log_fp);
        attack_log_fp = NULL;
    }
    
    if (access_log_fp) {
        fclose(access_log_fp);
        access_log_fp = NULL;
    }
    
    if (error_log_fp) {
        fclose(error_log_fp);
        error_log_fp = NULL;
    }
    
    if (audit_log_fp) {
        fclose(audit_log_fp);
        audit_log_fp = NULL;
    }
    
    pthread_mutex_unlock(&log_mutex);
}

int log_write_attack(attack_log_entry_t *entry) {
    if (!entry) return -1;
    
    pthread_mutex_lock(&log_mutex);
    
    if (!attack_log_fp) {
        pthread_mutex_unlock(&log_mutex);
        return -1;
    }
    
    char timestamp[64];
    struct tm *tm_info = localtime(&entry->timestamp);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(attack_log_fp, 
           "[%s] ATTACK | Type: %s | Severity: %d | Rule: %s | Action: %s\n",
           timestamp,
           entry->type < ATTACK_UNKNOWN ? attack_type_names[entry->type] : "UNKNOWN",
           entry->severity,
           entry->rule_id,
           entry->action == WAF_ACTION_BLOCK ? "BLOCK" : 
           entry->action == WAF_ACTION_LOG ? "LOG" : "ALLOW");
    
    fprintf(attack_log_fp, 
           "      | IP: %s | Method: %s | Path: %s\n",
           entry->ip,
           entry->method,
           entry->path);
    
    if (entry->query[0]) {
        fprintf(attack_log_fp, 
               "      | Query: %s\n",
               entry->query);
    }
    
    if (entry->matched_content[0]) {
        fprintf(attack_log_fp, 
               "      | Matched: %s\n",
               entry->matched_content);
    }
    
    if (entry->attack_pattern[0]) {
        fprintf(attack_log_fp, 
               "      | Pattern: %s\n",
               entry->attack_pattern);
    }
    
    if (entry->description[0]) {
        fprintf(attack_log_fp, 
               "      | Desc: %s\n",
               entry->description);
    }
    
    if (entry->user_agent[0]) {
        fprintf(attack_log_fp, 
               "      | UA: %s\n",
               entry->user_agent);
    }
    
    if (entry->referer[0]) {
        fprintf(attack_log_fp, 
               "      | Referer: %s\n",
               entry->referer);
    }
    
    if (entry->request_body[0]) {
        fprintf(attack_log_fp, 
               "      | Body: %s\n",
               entry->request_body);
    }
    
    fprintf(attack_log_fp, "      +----------------------------------------\n");
    
    fflush(attack_log_fp);
    maintain_locked();
    
    pthread_mutex_unlock(&log_mutex);
    return 0;
}

int log_write_access(access_log_entry_t *entry) {
    if (!entry) return -1;
    
    pthread_mutex_lock(&log_mutex);
    
    if (!access_log_fp) {
        pthread_mutex_unlock(&log_mutex);
        return -1;
    }
    
    char timestamp[64];
    struct tm *tm_info = localtime(&entry->timestamp);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(access_log_fp,
           "[%s] %s %s %s %d %zu %zu %dms - %s\n",
           timestamp,
           entry->ip,
           entry->method,
           entry->url,
           entry->status_code,
           entry->bytes_sent,
           entry->bytes_received,
           entry->response_time,
           entry->user_agent);
    
    fflush(access_log_fp);
    maintain_locked();
    
    pthread_mutex_unlock(&log_mutex);
    return 0;
}

int log_write_error(const char *format, ...) {
    pthread_mutex_lock(&log_mutex);
    
    if (!error_log_fp) {
        pthread_mutex_unlock(&log_mutex);
        return -1;
    }
    
    time_t now = time(NULL);
    char timestamp[64];
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(error_log_fp, "[%s] ERROR: ", timestamp);
    
    va_list args;
    va_start(args, format);
    vfprintf(error_log_fp, format, args);
    va_end(args);
    
    fprintf(error_log_fp, "\n");
    fflush(error_log_fp);
    maintain_locked();
    
    pthread_mutex_unlock(&log_mutex);
    return 0;
}

int log_write_audit(const char *format, ...) {
    pthread_mutex_lock(&log_mutex);
    
    if (!audit_log_fp) {
        pthread_mutex_unlock(&log_mutex);
        return -1;
    }
    
    time_t now = time(NULL);
    char timestamp[64];
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(audit_log_fp, "[%s] AUDIT: ", timestamp);
    
    va_list args;
    va_start(args, format);
    vfprintf(audit_log_fp, format, args);
    va_end(args);
    
    fprintf(audit_log_fp, "\n");
    fflush(audit_log_fp);
    maintain_locked();
    
    pthread_mutex_unlock(&log_mutex);
    return 0;
}

int log_rotate(void) {
    pthread_mutex_lock(&log_mutex);

    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y%m%d-%H%M%S", &tm_now);

    in_rotate = 1;
    rotate_one_locked(&attack_log_fp, "waf-attack.log", timestamp);
    rotate_one_locked(&access_log_fp, "waf-access.log", timestamp);
    rotate_one_locked(&error_log_fp,  "waf-error.log",  timestamp);
    rotate_one_locked(&audit_log_fp,  "waf-audit.log",  timestamp);
    in_rotate = 0;

    pthread_mutex_unlock(&log_mutex);

    waf_log(LOG_LEVEL_INFO, "Log rotation completed");
    return 0;
}

int log_backup(void) {
    waf_log(LOG_LEVEL_INFO, "Log backup not implemented yet");
    return 0;
}

int log_cleanup(int days) {
    if (days <= 0) return -1;

    pthread_mutex_lock(&log_mutex);
    int saved = retention_days;
    retention_days = days;
    in_rotate = 1;
    cleanup_locked();
    in_rotate = 0;
    retention_days = saved;
    pthread_mutex_unlock(&log_mutex);

    return 0;
}

int log_get_stats(void) {
    return 0;
}

void log_set_level(int level) {
    log_level = level;
}
