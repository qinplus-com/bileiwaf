#ifndef WAF_RULES_H
#define WAF_RULES_H

#include "waf_common.h"
#include "waf_http.h"
#include "waf_ai.h"

typedef struct {
    char id[64];
    char name[128];
    attack_type_t type;
    char pattern[512];
    waf_action_t action;
    int severity;
    int enabled;
    regex_t regex;
} detection_rule_t;

typedef struct {
    char id[64];
    char name[128];
    char type[64];
    char value[512];
    waf_action_t action;
    int enabled;
} access_rule_t;

int rules_init(const char *rules_dir, void *waf_cfg);
void rules_destroy(void);
void rules_set_ai_config(ai_config_t *config);
int rules_load(void);
int rules_reload(void);
/* SIGHUP 安全重载：信号处理器仅置标志，请求线程在安全点执行实际 reload */
void rules_request_reload(void);
void rules_try_pending_reload(void);
int rules_check_request(http_request_t *req, attack_match_t *match);
int rules_check_sql_injection(const char *data, attack_match_t *match);
int rules_check_xss(const char *data, attack_match_t *match);
int rules_check_cmd_injection(const char *data, attack_match_t *match);
int rules_check_path_traversal(const char *data, attack_match_t *match);
int rules_check_file_upload(const char *data, attack_match_t *match);
int rules_check_csrf(const char *data, attack_match_t *match);
int rules_check_ssrf(const char *data, attack_match_t *match);
int rules_check_scanner(const char *data, attack_match_t *match);
int rules_check_xml_injection(const char *data, attack_match_t *match);
int rules_check_generic(const char *data, attack_type_t type, attack_match_t *match);
int access_check_ip(const char *ip);
int access_check_url(const char *url);
int access_check_user_agent(const char *ua);
int access_check_referer(const char *referer);

#endif
