#include "../include/waf_cc.h"
#include "../include/waf_log.h"
#include "../include/waf_common.h"
#include <sys/time.h>
#include <arpa/inet.h>
#include <stdint.h>

#define MAX_CC_ENTRIES 100000
#define DEFAULT_MAX_REQUESTS 100
#define DEFAULT_TIME_WINDOW 60
#define MAX_WHITELIST_IPS 1000
#define MAX_BLACKLIST_IPS 1000

static cc_config_t global_cc_config = {
    .enabled = 1,
    .max_requests = DEFAULT_MAX_REQUESTS,
    .time_window = DEFAULT_TIME_WINDOW,
    .action = WAF_ACTION_BLOCK,
    .block_duration = 300,
    .enable_captcha = 0
};

static cc_counter_t cc_counters[MAX_CC_ENTRIES];
static int cc_counters_count = 0;
static pthread_mutex_t cc_mutex = PTHREAD_MUTEX_INITIALIZER;

static char whitelist_ips[MAX_WHITELIST_IPS][64];
static int whitelist_count = 0;
/* IPv4 CIDR 网段白名单（搜索引擎官方 IP 段等）：net 为主机序网络地址，prefix 0-32 */
typedef struct { uint32_t net; int prefix; } wl_cidr_t;
static wl_cidr_t whitelist_cidrs[MAX_WHITELIST_IPS];
static int whitelist_cidr_count = 0;
static pthread_mutex_t whitelist_mutex = PTHREAD_MUTEX_INITIALIZER;

static char blacklist_ips[MAX_BLACKLIST_IPS][64];
static int blacklist_count = 0;
static pthread_mutex_t blacklist_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint32_t wl_prefix_mask(int prefix) {
    return prefix ? (0xFFFFFFFFu << (32 - prefix)) : 0u;
}

static int load_whitelist(const char *filename) {
    if (!filename) return -1;

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        waf_log(LOG_LEVEL_WARN, "Whitelist file not found: %s", filename);
        return -1;
    }

    pthread_mutex_lock(&whitelist_mutex);
    whitelist_count = 0;
    whitelist_cidr_count = 0;

    char line[256];
    while (fgets(line, sizeof(line), fp) && whitelist_count < MAX_WHITELIST_IPS) {
        char *ip = waf_trim(line);
        if (ip[0] == '#' || ip[0] == '\0') continue;

        /* IPv4 解析：支持纯 IP（视作 /32）与 IP/前缀（CIDR 网段）两种格式 */
        char ipbuf[64];
        strncpy(ipbuf, ip, sizeof(ipbuf) - 1);
        ipbuf[sizeof(ipbuf) - 1] = '\0';
        char *slash = strchr(ipbuf, '/');
        if (slash) *slash = '\0';

        struct in_addr a;
        if (inet_pton(AF_INET, ipbuf, &a) == 1) {
            int prefix = slash ? atoi(slash + 1) : 32;
            if (prefix < 0 || prefix > 32 || (slash && strchr(slash + 1, '.'))) {
                waf_log(LOG_LEVEL_WARN, "Whitelist invalid IPv4/CIDR entry skipped: %s", ip);
                continue;
            }
            uint32_t host = (uint32_t)ntohl(a.s_addr);
            whitelist_cidrs[whitelist_cidr_count].net = host & wl_prefix_mask(prefix);
            whitelist_cidrs[whitelist_cidr_count].prefix = prefix;
            whitelist_cidr_count++;
            continue;
        }

        /* 非 IPv4（如 IPv6）保留文本精确匹配 */
        strncpy(whitelist_ips[whitelist_count], ip, 63);
        whitelist_ips[whitelist_count][63] = '\0';
        whitelist_count++;
    }

    fclose(fp);
    pthread_mutex_unlock(&whitelist_mutex);

    waf_log(LOG_LEVEL_INFO, "Loaded %d whitelisted IPs (+%d CIDR ranges) from %s",
            whitelist_count, whitelist_cidr_count, filename);
    return 0;
}

static int load_blacklist(const char *filename) {
    if (!filename) return -1;

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        waf_log(LOG_LEVEL_WARN, "Blacklist file not found: %s", filename);
        return -1;
    }

    pthread_mutex_lock(&blacklist_mutex);
    blacklist_count = 0;

    char line[256];
    while (fgets(line, sizeof(line), fp) && blacklist_count < MAX_BLACKLIST_IPS) {
        char *ip = waf_trim(line);
        if (ip[0] == '#' || ip[0] == '\0') continue;

        strncpy(blacklist_ips[blacklist_count], ip, 63);
        blacklist_ips[blacklist_count][63] = '\0';
        blacklist_count++;
    }

    fclose(fp);
    pthread_mutex_unlock(&blacklist_mutex);

    waf_log(LOG_LEVEL_INFO, "Loaded %d blacklisted IPs from %s", blacklist_count, filename);
    return 0;
}

int is_ip_blacklisted(const char *ip) {
    if (!ip) return 0;

    pthread_mutex_lock(&blacklist_mutex);
    for (int i = 0; i < blacklist_count; i++) {
        if (strcmp(blacklist_ips[i], ip) == 0) {
            pthread_mutex_unlock(&blacklist_mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&blacklist_mutex);
    return 0;
}

int is_ip_whitelisted(const char *ip) {
    if (!ip) return 0;

    pthread_mutex_lock(&whitelist_mutex);
    for (int i = 0; i < whitelist_count; i++) {
        if (strcmp(whitelist_ips[i], ip) == 0) {
            pthread_mutex_unlock(&whitelist_mutex);
            return 1;
        }
    }

    /* IPv4 CIDR 网段前缀匹配（搜索引擎官方网段等） */
    struct in_addr a;
    if (inet_pton(AF_INET, ip, &a) == 1) {
        uint32_t host = (uint32_t)ntohl(a.s_addr);
        for (int i = 0; i < whitelist_cidr_count; i++) {
            if ((host & wl_prefix_mask(whitelist_cidrs[i].prefix)) == whitelist_cidrs[i].net) {
                pthread_mutex_unlock(&whitelist_mutex);
                return 1;
            }
        }
    }

    pthread_mutex_unlock(&whitelist_mutex);
    return 0;
}

int is_ip_allowed(const char *ip) {
    if (!ip) return 0;

    /* 白名单优先级最高：白名单 IP 豁免全部 IP 级限制（黑名单拦截、CC 限流等），
     * 攻击检测（规则/AI）不受影响，仍照常执行并记录。 */
    if (is_ip_whitelisted(ip)) {
        return 1;
    }

    if (is_ip_blacklisted(ip)) {
        return 0;
    }

    return 1;
}

int cc_init(cc_config_t *config) {
    if (config) {
        memcpy(&global_cc_config, config, sizeof(cc_config_t));
    }

    /* Allow env overrides (used by portable/demo deployments) */
    {
        const char *env;
        if ((env = getenv("WAF_CC_MAX_REQUESTS")) && env[0])
            global_cc_config.max_requests = atoi(env);
        if ((env = getenv("WAF_CC_TIME_WINDOW")) && env[0])
            global_cc_config.time_window = atoi(env);
        if ((env = getenv("WAF_CC_BLOCK_DURATION")) && env[0])
            global_cc_config.block_duration = atoi(env);
    }

    memset(cc_counters, 0, sizeof(cc_counters));
    cc_counters_count = 0;

    load_whitelist("rules/whitelist.ip");
    load_blacklist("rules/blacklist.ip");

    waf_log(LOG_LEVEL_INFO, "CC protection initialized: max=%d, window=%ds",
           global_cc_config.max_requests, global_cc_config.time_window);

    return 0;
}

void cc_destroy(void) {
    pthread_mutex_lock(&cc_mutex);
    memset(cc_counters, 0, sizeof(cc_counters));
    cc_counters_count = 0;
    pthread_mutex_unlock(&cc_mutex);
}

int cc_check_request(const char *ip, http_request_t *req __attribute__((unused))) {
    if (!global_cc_config.enabled) return 0;
    if (!ip) return 0;

    /* 白名单 IP 置于最前：豁免 CC 限流与黑名单拦截。攻击检测在后续流程中照常执行。 */
    if (is_ip_whitelisted(ip)) {
        return 0;
    }

    if (is_ip_blacklisted(ip)) {
        waf_log(LOG_LEVEL_WARN, "IP %s is blacklisted, blocked", ip);
        return 1;
    }

    pthread_mutex_lock(&cc_mutex);

    time_t now = time(NULL);

    for (int i = 0; i < cc_counters_count; i++) {
        cc_counter_t *counter = &cc_counters[i];

        if (counter->blocked) {
            if (now - counter->last_request > global_cc_config.block_duration) {
                counter->blocked = 0;
                counter->request_count = 0;
            } else {
                pthread_mutex_unlock(&cc_mutex);
                return 1;
            }
        }

        if (now - counter->first_request > global_cc_config.time_window) {
            counter->request_count = 0;
            counter->first_request = now;
        }
    }

    int found = -1;
    for (int i = 0; i < cc_counters_count; i++) {
        if (strcmp(cc_counters[i].ip, ip) == 0) {
            found = i;
            break;
        }
    }

    if (found >= 0) {
        cc_counters[found].request_count++;
        cc_counters[found].last_request = now;

        if (cc_counters[found].request_count > global_cc_config.max_requests) {
            /* v1.2.0：超阈值不再自动置 blocked——返回 2 由调用方决策
             * （站点开人机验证 → 302 挑战；未开 → cc_block_ip 原语义） */
            waf_log(LOG_LEVEL_WARN, "CC threshold exceeded from IP: %s, count: %d",
                   ip, cc_counters[found].request_count);
            pthread_mutex_unlock(&cc_mutex);
            return 2;
        }
    } else if (cc_counters_count < MAX_CC_ENTRIES) {
        strncpy(cc_counters[cc_counters_count].ip, ip, MAX_IP_LENGTH - 1);
        cc_counters[cc_counters_count].first_request = now;
        cc_counters[cc_counters_count].last_request = now;
        cc_counters[cc_counters_count].request_count = 1;
        cc_counters[cc_counters_count].blocked = 0;
        cc_counters_count++;
    }

    pthread_mutex_unlock(&cc_mutex);
    return 0;
}

int cc_is_blocked(const char *ip) {
    if (!ip) return 0;

    pthread_mutex_lock(&cc_mutex);
    time_t now = time(NULL);
    int blocked = 0;
    for (int i = 0; i < cc_counters_count; i++) {
        cc_counter_t *counter = &cc_counters[i];
        if (counter->blocked) {
            if (now - counter->last_request > global_cc_config.block_duration) {
                counter->blocked = 0;
                counter->request_count = 0;
            } else if (strcmp(counter->ip, ip) == 0) {
                blocked = 1;
                break;
            }
        }
    }
    pthread_mutex_unlock(&cc_mutex);
    return blocked;
}

int cc_reset_ip(const char *ip) {
    if (!ip) return -1;

    pthread_mutex_lock(&cc_mutex);
    for (int i = 0; i < cc_counters_count; i++) {
        if (strcmp(cc_counters[i].ip, ip) == 0) {
            cc_counters[i].request_count = 0;
            cc_counters[i].blocked = 0;
            cc_counters[i].first_request = time(NULL);
            waf_log(LOG_LEVEL_INFO, "CC counter reset (human verified): %s", ip);
            pthread_mutex_unlock(&cc_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&cc_mutex);
    return -1;
}

int cc_block_duration(void) {
    return global_cc_config.block_duration;
}

int cc_block_ip(const char *ip, int duration) {
    if (!ip) return -1;

    pthread_mutex_lock(&cc_mutex);

    for (int i = 0; i < cc_counters_count; i++) {
        if (strcmp(cc_counters[i].ip, ip) == 0) {
            cc_counters[i].blocked = 1;
            waf_log(LOG_LEVEL_WARN, "IP manually blocked: %s for %d seconds", ip, duration);
            pthread_mutex_unlock(&cc_mutex);
            return 0;
        }
    }

    if (cc_counters_count < MAX_CC_ENTRIES) {
        strncpy(cc_counters[cc_counters_count].ip, ip, MAX_IP_LENGTH - 1);
        cc_counters[cc_counters_count].blocked = 1;
        cc_counters[cc_counters_count].request_count = 0;
        cc_counters[cc_counters_count].first_request = time(NULL);
        cc_counters[cc_counters_count].last_request = time(NULL);
        cc_counters_count++;
        waf_log(LOG_LEVEL_WARN, "IP blocked: %s for %d seconds", ip, duration);
        pthread_mutex_unlock(&cc_mutex);
        return 0;
    }

    pthread_mutex_unlock(&cc_mutex);
    return -1;
}

int cc_unblock_ip(const char *ip) {
    if (!ip) return -1;

    pthread_mutex_lock(&cc_mutex);

    for (int i = 0; i < cc_counters_count; i++) {
        if (strcmp(cc_counters[i].ip, ip) == 0) {
            cc_counters[i].blocked = 0;
            cc_counters[i].request_count = 0;
            waf_log(LOG_LEVEL_INFO, "IP unblocked: %s", ip);
            pthread_mutex_unlock(&cc_mutex);
            return 0;
        }
    }

    pthread_mutex_unlock(&cc_mutex);
    return -1;
}

int cc_get_blocked_count(void) {
    int count = 0;

    pthread_mutex_lock(&cc_mutex);
    for (int i = 0; i < cc_counters_count; i++) {
        if (cc_counters[i].blocked) {
            count++;
        }
    }
    pthread_mutex_unlock(&cc_mutex);

    return count;
}

void cc_cleanup_old_records(void) {
    pthread_mutex_lock(&cc_mutex);

    time_t now = time(NULL);
    int write_idx = 0;

    for (int i = 0; i < cc_counters_count; i++) {
        if (!cc_counters[i].blocked &&
            now - cc_counters[i].last_request < global_cc_config.time_window * 10) {
            if (write_idx != i) {
                cc_counters[write_idx] = cc_counters[i];
            }
            write_idx++;
        }
    }

    cc_counters_count = write_idx;

    pthread_mutex_unlock(&cc_mutex);
}

int cc_load_config(const char *config_file) {
    if (!config_file) return -1;

    FILE *fp = fopen(config_file, "r");
    if (!fp) {
        waf_log(LOG_LEVEL_ERROR, "Failed to open CC config file: %s", config_file);
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "\n");

        if (!key || !value) continue;

        if (strcmp(key, "enabled") == 0) {
            global_cc_config.enabled = atoi(value);
        } else if (strcmp(key, "max_requests") == 0) {
            global_cc_config.max_requests = atoi(value);
        } else if (strcmp(key, "time_window") == 0) {
            global_cc_config.time_window = atoi(value);
        } else if (strcmp(key, "block_duration") == 0) {
            global_cc_config.block_duration = atoi(value);
        }
    }

    fclose(fp);

    waf_log(LOG_LEVEL_INFO, "CC config loaded: enabled=%d, max=%d, window=%ds",
           global_cc_config.enabled, global_cc_config.max_requests,
           global_cc_config.time_window);

    return 0;
}

int cc_save_config(const char *config_file) {
    if (!config_file) return -1;

    FILE *fp = fopen(config_file, "w");
    if (!fp) {
        waf_log(LOG_LEVEL_ERROR, "Failed to save CC config file: %s", config_file);
        return -1;
    }

    fprintf(fp, "enabled=%d\n", global_cc_config.enabled);
    fprintf(fp, "max_requests=%d\n", global_cc_config.max_requests);
    fprintf(fp, "time_window=%d\n", global_cc_config.time_window);
    fprintf(fp, "block_duration=%d\n", global_cc_config.block_duration);
    fprintf(fp, "enable_captcha=%d\n", global_cc_config.enable_captcha);

    fclose(fp);

    return 0;
}

int rate_limit_init(void) {
    waf_log(LOG_LEVEL_INFO, "Rate limiting initialized");
    return 0;
}

void rate_limit_destroy(void) {
    waf_log(LOG_LEVEL_INFO, "Rate limiting destroyed");
}

int rate_limit_check(const char *ip, const char *url __attribute__((unused))) {
    if (!ip) return 0;
    return 0;
}

int rate_limit_inc(const char *ip, const char *url __attribute__((unused))) {
    if (!ip) return -1;
    return 0;
}
