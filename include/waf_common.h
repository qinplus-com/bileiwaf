#ifndef WAF_COMMON_H
#define WAF_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <regex.h>
#include <ctype.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>

#define MAX_REQUEST_SIZE 65536
#define MAX_URL_LENGTH 8192
#define MAX_HEADER_SIZE 8192
#define MAX_BODY_SIZE 65536
#define MAX_IP_LENGTH 16
#define MAX_CONFIG_LINE 1024
#define MAX_RULES 10000
#define MAX_BLOCKLIST 100000
#define MAX_LOG_SIZE 1024*1024

/* ---- OpenSSL 兼容层（el7 / OpenSSL 1.0.2）----
 * TLS_server_method / SSL_CTX_set_min_proto_version / SSL_CTX_set_security_level
 * 均为 1.1.0 起引入；1.0.2 下用旧接口等价实现，使同一份源码既能在
 * el7（OpenSSL 1.0.2）也能在 el8+（1.1/3.x）编译。 */
#if defined(USE_OPENSSL)
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define TLS_server_method SSLv23_server_method
#define TLS_client_method SSLv23_client_method
#define SSL_CTX_set_security_level(ctx, level) ((void)(ctx), (void)(level))
#define SSL_CTX_set_min_proto_version(ctx, v) \
    SSL_CTX_set_options((ctx), \
        (((v) > TLS1_VERSION)   ? SSL_OP_NO_TLSv1   : 0) | \
        (((v) > TLS1_1_VERSION) ? SSL_OP_NO_TLSv1_1 : 0))
#endif
#endif

typedef enum {
    WAF_MODE_LEARNING = 0,
    WAF_MODE_DETECTION = 1,
    WAF_MODE_BLOCKING = 2
} waf_mode_t;

typedef enum {
    DETECTION_MODE_RULES = 0,
    DETECTION_MODE_AI = 1,
    DETECTION_MODE_AUTO = 2
} detection_mode_t;

typedef enum {
    WAF_ACTION_ALLOW = 0,
    WAF_ACTION_BLOCK = 1,
    WAF_ACTION_LOG = 2,
    WAF_ACTION_REDIRECT = 3
} waf_action_t;

typedef enum {
    ATTACK_SQL_INJECTION = 0,
    ATTACK_XSS = 1,
    ATTACK_CMD_INJECTION = 2,
    ATTACK_PATH_TRAVERSAL = 3,
    ATTACK_FILE_UPLOAD = 4,
    ATTACK_CSRF = 5,
    ATTACK_LDAP_INJECTION = 6,
    ATTACK_XML_INJECTION = 7,
    ATTACK_JSON_INJECTION = 8,
    ATTACK_SSRF = 9,
    ATTACK_DESERIALIZATION = 10,
    ATTACK_SCANNER = 11,
    ATTACK_CC = 12,
    ATTACK_MALICIOUS_BOT = 13,
    ATTACK_BRUTE_FORCE = 14,
    ATTACK_API_ABUSE = 15,
    ATTACK_UNKNOWN = 99
} attack_type_t;

typedef enum {
    PROTOCOL_HTTP = 0,
    PROTOCOL_HTTPS = 1
} protocol_t;

typedef struct {
    char method[16];
    char url[MAX_URL_LENGTH];
    char path[MAX_URL_LENGTH];
    char query[MAX_URL_LENGTH];
    char version[16];
    protocol_t protocol;
    char headers[MAX_HEADER_SIZE];
    char body[MAX_BODY_SIZE];
    size_t headers_len;
    size_t body_len;
    char client_ip[MAX_IP_LENGTH];
    int client_port;
    time_t timestamp;
    unsigned long long start_time;
} http_request_t;

typedef struct {
    int status_code;
    char status_message[64];
    char headers[MAX_HEADER_SIZE];
    char body[MAX_BODY_SIZE];
    size_t headers_len;
    size_t body_len;
} http_response_t;

typedef struct {
    attack_type_t type;
    char pattern[512];
    char matched_content[1024];
    int severity;
    char description[256];
    char rule_id[64];
} attack_match_t;

typedef struct {
    waf_action_t action;
    waf_mode_t mode;
    char rule_id[64];
    attack_match_t match;
} waf_result_t;

typedef struct {
    char ip[MAX_IP_LENGTH];
    time_t timestamp;
    int blocked;
} ip_record_t;

typedef struct {
    char pattern[512];
    int enabled;
    attack_type_t attack_type;
    waf_action_t action;
    int severity;
    regex_t regex;
} waf_rule_t;

typedef struct {
    int enabled;
    int max_requests;
    int time_window;
    waf_action_t action;
} cc_rule_t;

typedef struct {
    int enabled;
    char ip[MAX_IP_LENGTH];
    time_t timestamp;
    int count;
    int blocked;
} rate_limit_t;

void waf_log(int level, const char *format, ...);
void waf_hex_dump(const char *data, size_t len);
char* waf_trim(char *str);
int waf_hex_decode(const char *src, char *dst, size_t dst_size);
int waf_url_decode(const char *src, char *dst, size_t dst_size);
int waf_normalize_path(const char *path, char *normalized, size_t norm_size);
time_t waf_get_timestamp(void);
void waf_get_timestamp_str(char *buf, size_t size);
unsigned long waf_hash_string(const char *str);
int waf_ip_match(const char *ip, const char *cidr);
int waf_parse_ip_range(const char *range, struct in_addr *start, struct in_addr *end);
int waf_itoa(int value, char *str, size_t size);

#endif
