#ifndef WAF_CC_H
#define WAF_CC_H

#include "waf_common.h"

typedef struct {
    char ip[MAX_IP_LENGTH];
    time_t first_request;
    time_t last_request;
    int request_count;
    int blocked;
} cc_counter_t;

typedef struct {
    int enabled;
    int max_requests;
    int time_window;
    waf_action_t action;
    int block_duration;
    int enable_captcha;
} cc_config_t;

int cc_init(cc_config_t *config);
void cc_destroy(void);
/* 返回值：0=正常放行；1=封禁态（blocked，应 403）；
 * 2=本次请求刚超阈值（不自动封禁，由调用方决定封禁或转人机验证） */
int cc_check_request(const char *ip, http_request_t *req);
int cc_block_ip(const char *ip, int duration);
int cc_unblock_ip(const char *ip);
int cc_get_blocked_count(void);
void cc_cleanup_old_records(void);
int cc_load_config(const char *config_file);
int cc_save_config(const char *config_file);

/* 人机验证支撑（v1.2.0） */
int cc_is_blocked(const char *ip);     /* 封禁态查询（验证码端点不出题） */
int cc_reset_ip(const char *ip);       /* 清计数+解除封禁（验证通过后调用） */
int cc_block_duration(void);           /* 当前封禁时长配置（秒） */

int is_ip_allowed(const char *ip);
int is_ip_blacklisted(const char *ip);
/* 白名单 IP 查询：白名单 IP 豁免全部 IP 级限制（黑名单拦截、CC 限流），
 * 但仍参与规则/AI 攻击检测。 */
int is_ip_whitelisted(const char *ip);

int rate_limit_init(void);
void rate_limit_destroy(void);
int rate_limit_check(const char *ip, const char *url);
int rate_limit_inc(const char *ip, const char *url);

#endif
