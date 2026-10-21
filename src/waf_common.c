#include "../include/waf_common.h"
#include "../include/waf_log.h"
#include <stdarg.h>

static int waf_hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO  1
#define LOG_LEVEL_WARN  2
#define LOG_LEVEL_ERROR 3
#define LOG_LEVEL_FATAL 4

static int global_log_level = LOG_LEVEL_INFO;

void waf_log(int level, const char *format, ...) {
    if (level < global_log_level) return;
    
    va_list args;
    va_start(args, format);
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    const char *level_str[] = {"DEBUG", "INFO", "WARN", "ERROR", "FATAL"};
    
    char log_msg[2048];
    vsnprintf(log_msg, sizeof(log_msg), format, args);
    
    fprintf(stdout, "[%s] [%s] %s\n", timestamp, level_str[level], log_msg);
    fflush(stdout);
    
    if (level >= LOG_LEVEL_WARN) {
        log_write_error("[%s] %s", level_str[level], log_msg);
    }
    
    va_end(args);
}

void waf_hex_dump(const char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        fprintf(stdout, "%02x ", (unsigned char)data[i]);
        if ((i + 1) % 16 == 0) {
            fprintf(stdout, "\n");
        }
    }
    fprintf(stdout, "\n");
    fflush(stdout);
}

char* waf_trim(char *str) {
    if (!str) return NULL;
    
    while (isspace((unsigned char)*str)) str++;
    
    if (*str == 0) return str;
    
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    
    end[1] = '\0';
    return str;
}

int waf_hex_decode(const char *src, char *dst, size_t dst_size) {
    if (!src || !dst) return -1;
    
    size_t src_len = strlen(src);
    if (src_len % 2 != 0) return -1;
    
    size_t dst_len = src_len / 2;
    if (dst_len >= dst_size) return -1;
    
    for (size_t i = 0; i < src_len; i += 2) {
        char hex[3] = {src[i], src[i+1], '\0'};
        unsigned int val;
        if (sscanf(hex, "%02x", &val) != 1) return -1;
        dst[i/2] = (char)val;
    }
    
    dst[dst_len] = '\0';
    return (int)dst_len;
}

int waf_url_decode(const char *src, char *dst, size_t dst_size) {
    if (!src || !dst) return -1;
    
    size_t src_pos = 0;
    size_t dst_pos = 0;
    size_t src_len = strlen(src);
    
    while (src_pos < src_len && dst_pos < dst_size - 1) {
        if (src[src_pos] == '%') {
            if (src_pos + 2 < src_len) {
                /* 严格校验两个 hex 位: sscanf("%02x") 对 "%ev" 这类单 hex 位
                 * 会误判成功并吃掉 3 字节,破坏载荷(如 <%eval -> <\x0eal) */
                int h1 = waf_hex_val(src[src_pos+1]);
                int h2 = waf_hex_val(src[src_pos+2]);
                if (h1 >= 0 && h2 >= 0) {
                    unsigned int val = (unsigned int)((h1 << 4) | h2);
                    /* %00 会产生内嵌 NUL,导致后续 C 字符串处理在 NUL 处截断,
                     * 攻击者借此把载荷藏在 %00 之后;替换为空格保留可见性 */
                    dst[dst_pos++] = val ? (char)val : ' ';
                    src_pos += 3;
                } else {
                    dst[dst_pos++] = src[src_pos++];
                }
            } else {
                dst[dst_pos++] = src[src_pos++];
            }
        } else if (src[src_pos] == '+') {
            dst[dst_pos++] = ' ';
            src_pos++;
        } else {
            dst[dst_pos++] = src[src_pos++];
        }
    }
    
    dst[dst_pos] = '\0';
    return (int)dst_pos;
}

int waf_normalize_path(const char *path, char *normalized, size_t norm_size) {
    if (!path || !normalized) return -1;
    
    size_t path_len = strlen(path);
    if (path_len >= norm_size) return -1;
    
    size_t pos = 0;
    size_t i = 0;
    
    if (path_len > 0 && path[0] == '/') {
        normalized[pos++] = '/';
        i++;
    }
    
    while (i < path_len && pos < norm_size - 1) {
        if (path[i] == '/') {
            i++;
            continue;
        }
        
        if (i + 1 < path_len && path[i] == '.' && path[i+1] == '.') {
            if (pos > 1) {
                pos--;
                while (pos > 1 && normalized[pos-1] != '/') {
                    pos--;
                }
            }
            i += 2;
        } else if (i < path_len && path[i] == '.') {
            i++;
        } else {
            while (i < path_len && path[i] != '/' && pos < norm_size - 1) {
                normalized[pos++] = path[i++];
            }
            if (i < path_len && path[i] == '/' && pos < norm_size - 1) {
                normalized[pos++] = '/';
                i++;
            }
        }
    }
    
    if (pos > 1 && normalized[pos-1] == '/') {
        pos--;
    }
    
    normalized[pos] = '\0';
    return (int)pos;
}

time_t waf_get_timestamp(void) {
    return time(NULL);
}

void waf_get_timestamp_str(char *buf, size_t size) {
    if (!buf) return;
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

unsigned long waf_hash_string(const char *str) {
    if (!str) return 0;
    
    unsigned long hash = 5381;
    int c;
    
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    
    return hash;
}

int waf_ip_match(const char *ip, const char *cidr) {
    if (!ip || !cidr) return 0;
    
    struct in_addr ip_addr, net_addr, mask_addr;
    
    if (inet_aton(ip, &ip_addr) == 0) return 0;
    
    char cidr_copy[64];
    strncpy(cidr_copy, cidr, sizeof(cidr_copy) - 1);
    cidr_copy[sizeof(cidr_copy) - 1] = '\0';
    
    char *slash = strchr(cidr_copy, '/');
    int prefix_len = 32;
    
    if (slash) {
        *slash = '\0';
        prefix_len = atoi(slash + 1);
    }
    
    if (inet_aton(cidr_copy, &net_addr) == 0) return 0;
    
    uint32_t mask = prefix_len == 0 ? 0 : (0xFFFFFFFF << (32 - prefix_len));
    mask_addr.s_addr = htonl(mask);
    
    return (ip_addr.s_addr & mask_addr.s_addr) == (net_addr.s_addr & mask_addr.s_addr);
}

int waf_parse_ip_range(const char *range, struct in_addr *start, struct in_addr *end) {
    if (!range || !start || !end) return -1;
    
    char range_copy[64];
    strncpy(range_copy, range, sizeof(range_copy) - 1);
    range_copy[sizeof(range_copy) - 1] = '\0';
    
    char *dash = strchr(range_copy, '-');
    
    if (dash) {
        *dash = '\0';
        if (inet_aton(waf_trim(range_copy), start) == 0) return -1;
        if (inet_aton(waf_trim(dash + 1), end) == 0) return -1;
    } else {
        if (inet_aton(range, start) == 0) return -1;
        *end = *start;
    }
    
    return 0;
}

int waf_itoa(int value, char *str, size_t size) {
    if (!str || size == 0) return -1;
    
    snprintf(str, size, "%d", value);
    return 0;
}
