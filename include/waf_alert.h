#ifndef WAF_ALERT_H
#define WAF_ALERT_H

#include <stdbool.h>

typedef struct {
    char email[256];
    char webhook_url[512];
    bool email_enabled;
    bool webhook_enabled;
    bool anomaly_alert_enabled;
    int anomaly_threshold;
    int attack_count_alert;
} alert_config_t;

void alert_init(alert_config_t *config);
void alert_cleanup(alert_config_t *config);
void alert_attack_detected(const char *ip, const char *attack_type, const char *details);
void alert_anomaly_detected(const char *anomaly_type, const char *details);
void alert_cc_attack(const char *ip, int count);
void alert_ip_blocked(const char *ip, const char *reason);
void alert_system_error(const char *error_msg);
int alert_send_email(const char *to, const char *subject, const char *body);
int alert_send_webhook(const char *url, const char *json_data);

#endif
