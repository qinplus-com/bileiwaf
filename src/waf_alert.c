#include "waf_alert.h"
#include "waf_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <curl/curl.h>

static int attack_count = 0;
static time_t last_alert_time = 0;
static const int ALERT_COOLDOWN = 300;

void alert_init(alert_config_t *config) {
    memset(config, 0, sizeof(alert_config_t));
    config->email_enabled = false;
    config->webhook_enabled = false;
    config->anomaly_alert_enabled = true;
    config->anomaly_threshold = 100;
    config->attack_count_alert = 50;
    waf_log(LOG_LEVEL_INFO, "Alert system initialized");
}

void alert_cleanup(alert_config_t *config) {
    waf_log(LOG_LEVEL_INFO, "Alert system cleanup");
}

void alert_attack_detected(const char *ip, const char *attack_type, const char *details) {
    attack_count++;
    time_t now = time(NULL);
    
    if (now - last_alert_time < ALERT_COOLDOWN) {
        return;
    }
    
    if (attack_count >= 10) {
        waf_log(LOG_LEVEL_ERROR, "ALERT: Multiple attacks detected - %d attacks in session", attack_count);
        
        char subject[256];
        char body[1024];
        snprintf(subject, sizeof(subject), "[WAF Alert] 多次攻击检测 - %d次攻击", attack_count);
        snprintf(body, sizeof(body), 
            "检测到多次攻击！\n\n"
            "攻击次数: %d\n"
            "最近攻击IP: %s\n"
            "攻击类型: %s\n"
            "详情: %s\n"
            "时间: %s",
            attack_count,
            ip ? ip : "未知",
            attack_type ? attack_type : "未知",
            details ? details : "无",
            ctime(&now)
        );
        
        waf_log(LOG_LEVEL_ERROR, "Attack alert: %s from %s - %s", attack_type, ip, details);
        
        attack_count = 0;
        last_alert_time = now;
    }
}

void alert_anomaly_detected(const char *anomaly_type, const char *details) {
    time_t now = time(NULL);
    
    if (now - last_alert_time < ALERT_COOLDOWN) {
        return;
    }
    
    waf_log(LOG_LEVEL_WARN, "ANOMALY DETECTED: %s - %s", anomaly_type, details);
    
    char subject[256];
    char body[1024];
    snprintf(subject, sizeof(subject), "[WAF Alert] 异常流量检测 - %s", anomaly_type);
    snprintf(body, sizeof(body), 
        "检测到异常流量！\n\n"
        "异常类型: %s\n"
        "详情: %s\n"
        "时间: %s\n\n"
        "建议: 检查是否为DDoS攻击或异常访问模式",
        anomaly_type,
        details ? details : "无",
        ctime(&now)
    );
    
    last_alert_time = now;
}

void alert_cc_attack(const char *ip, int count) {
    waf_log(LOG_LEVEL_ERROR, "CC ATTACK ALERT: IP %s has %d requests", ip, count);
    
    time_t now = time(NULL);
    char subject[256];
    char body[1024];
    snprintf(subject, sizeof(subject), "[WAF Alert] CC攻击检测 - IP: %s", ip);
    snprintf(body, sizeof(body), 
        "检测到CC攻击！\n\n"
        "攻击IP: %s\n"
        "请求次数: %d\n"
        "时间: %s\n\n"
        "WAF已自动封禁该IP",
        ip,
        count,
        ctime(&now)
    );
}

void alert_ip_blocked(const char *ip, const char *reason) {
    waf_log(LOG_LEVEL_INFO, "IP Blocked: %s - %s", ip, reason);
    
    char subject[256];
    char body[1024];
    time_t now = time(NULL);
    snprintf(subject, sizeof(subject), "[WAF Alert] IP被封禁 - %s", ip);
    snprintf(body, sizeof(body), 
        "IP已被WAF封禁\n\n"
        "IP地址: %s\n"
        "原因: %s\n"
        "时间: %s",
        ip,
        reason ? reason : "未知",
        ctime(&now)
    );
}

void alert_system_error(const char *error_msg) {
    waf_log(LOG_LEVEL_ERROR, "SYSTEM ERROR: %s", error_msg);
    
    time_t now = time(NULL);
    char subject[256];
    char body[2048];
    snprintf(subject, sizeof(subject), "[WAF Alert] 系统错误");
    snprintf(body, sizeof(body), 
        "WAF系统发生错误！\n\n"
        "错误信息: %s\n"
        "时间: %s\n\n"
        "请立即检查系统状态！",
        error_msg,
        ctime(&now)
    );
}

int alert_send_email(const char *to, const char *subject, const char *body) {
    if (!to || !subject || !body) {
        return -1;
    }
    
    FILE *fp = popen("/usr/sbin/sendmail -t", "w");
    if (!fp) {
        waf_log(LOG_LEVEL_WARN, "Failed to open sendmail");
        return -1;
    }
    
    fprintf(fp, "To: %s\n", to);
    fprintf(fp, "Subject: %s\n", subject);
    fprintf(fp, "Content-Type: text/plain; charset=utf-8\n\n");
    fprintf(fp, "%s\n", body);
    
    int ret = pclose(fp);
    return ret == 0 ? 0 : -1;
}

int alert_send_webhook(const char *url, const char *json_data) {
    if (!url || !json_data) {
        return -1;
    }
    
    CURL *curl = curl_easy_init();
    if (!curl) {
        return -1;
    }
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    CURLcode res = curl_easy_perform(curl);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        waf_log(LOG_LEVEL_WARN, "Webhook send failed: %s", curl_easy_strerror(res));
        return -1;
    }
    
    return 0;
}
