#ifndef WAF_LOG_H
#define WAF_LOG_H

#include "waf_common.h"
#include "waf_http.h"

#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO  1
#define LOG_LEVEL_WARN  2
#define LOG_LEVEL_ERROR 3
#define LOG_LEVEL_FATAL 4

#define LOG_FILE_ATTACK "logs/waf-attack.log"
#define LOG_FILE_ACCESS "logs/waf-access.log"
#define LOG_FILE_ERROR  "logs/waf-error.log"
#define LOG_FILE_AUDIT  "logs/waf-audit.log"

typedef struct {
    time_t timestamp;
    attack_type_t type;
    char ip[MAX_IP_LENGTH];
    char url[MAX_URL_LENGTH];
    char path[MAX_URL_LENGTH];
    char query[MAX_URL_LENGTH];
    char attack_pattern[1024];
    char matched_content[1024];
    char description[256];
    char user_agent[512];
    char referer[512];
    char request_body[2048];
    char method[16];
    waf_action_t action;
    int blocked;
    char rule_id[64];
    int severity;
} attack_log_entry_t;

typedef struct {
    time_t timestamp;
    char ip[MAX_IP_LENGTH];
    char method[16];
    char url[MAX_URL_LENGTH];
    int status_code;
    size_t bytes_sent;
    size_t bytes_received;
    int response_time;
    char user_agent[512];
} access_log_entry_t;

int log_init(const char *log_dir);
void log_destroy(void);
int log_write_attack(attack_log_entry_t *entry);
int log_write_access(access_log_entry_t *entry);
int log_write_error(const char *format, ...);
int log_write_audit(const char *format, ...);
int log_rotate(void);
int log_backup(void);
int log_cleanup(int days);
/* 设置轮转策略：size_mb=单文件阈值(MB，0=关闭)；retention=归档保留天数(0=永久) */
void log_set_rotation(int size_mb, int retention);
int log_get_stats(void);
void log_set_level(int level);

#endif
