#define _GNU_SOURCE
#include "../include/waf_http.h"
#include "../include/waf_common.h"
#include "../include/waf_ssl.h"
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <time.h>

/* 预留HTTP方法定义 - 可扩展时使用 */
/* static const char *http_methods[] = {
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT", NULL
}; */

int http_parse_request(const char *data, size_t len, http_request_t *req) {
    if (!data || !req || len == 0) return -1;
    
    memset(req, 0, sizeof(http_request_t));
    
    char *line_start = (char*)data;
    char *line_end = strstr(line_start, "\r\n");
    if (!line_end) {
        line_end = strstr(line_start, "\n");
        if (!line_end) return -1;
    }
    
    size_t request_line_len = line_end - line_start;
    if (request_line_len >= MAX_URL_LENGTH) return -1;
    
    char request_line[MAX_URL_LENGTH];
    strncpy(request_line, line_start, request_line_len);
    request_line[request_line_len] = '\0';
    
    char *method_end = strchr(request_line, ' ');
    if (!method_end) return -1;
    
    size_t method_len = method_end - request_line;
    if (method_len >= sizeof(req->method)) return -1;
    
    strncpy(req->method, request_line, method_len);
    req->method[method_len] = '\0';
    
    char *url_start = method_end + 1;
    char *url_end = strrchr(url_start, ' ');
    if (!url_end) {
        url_end = request_line + request_line_len;
    }
    
    size_t url_len = url_end - url_start;
    if (url_len >= MAX_URL_LENGTH) return -1;
    
    strncpy(req->url, url_start, url_len);
    req->url[url_len] = '\0';
    
    char *version_start = url_end + 1;
    while (*version_start == ' ') version_start++;
    
    size_t version_len = request_line + request_line_len - version_start;
    if (version_len < sizeof(req->version)) {
        strncpy(req->version, version_start, version_len);
        req->version[version_len] = '\0';
    }
    
    http_parse_url(req->url, req);
    
    char *headers_start = line_end + 1;
    if (*headers_start == '\r') headers_start++;
    if (*headers_start == '\n') headers_start++;
    
    char *headers_end = strstr(headers_start, "\r\n\r\n");
    if (!headers_end) {
        headers_end = strstr(headers_start, "\n\n");
        if (!headers_end) return -1;
    }
    
    size_t headers_len = headers_end - headers_start;
    if (headers_len >= MAX_HEADER_SIZE) return -1;
    
    strncpy(req->headers, headers_start, headers_len);
    req->headers[headers_len] = '\0';
    req->headers_len = headers_len;
    
    /* headers_end 指向 "\r\n\r\n" 的首字符（或 "\n\n"），body 从整个分隔符之后开始。
     * 原逻辑 headers_end+1 再各跳一次 \r/\n 只跳了 2 字节，body 会多吃进一对 \r\n，
     * 导致转发给后端的请求 body 带前导空行（后端按 \r\n\r\n 解析时 body 错位）。 */
    char *body_start = (headers_end[0] == '\r') ? headers_end + 4 : headers_end + 2;
    
    size_t body_len = len - (body_start - data);
    if (body_len > 0 && body_len < MAX_BODY_SIZE) {
        /* memcpy 而非 strncpy：strncpy 遇源中内嵌 NUL 即停止并填零，
         * info.php\x00.jpg 之后的 <?php phpinfo(); 会整体丢失(检测与转发双丢)。
         * 复制后把内嵌 NUL 替换为空格，避免 C 字符串检查在 NUL 处截断。 */
        memcpy(req->body, body_start, body_len);
        req->body[body_len] = '\0';
        for (size_t i = 0; i < body_len; i++) {
            if (req->body[i] == '\0') req->body[i] = ' ';
        }
        req->body_len = body_len;
    }
    
    req->timestamp = time(NULL);
    
    return 0;
}

int http_parse_headers(const char *data, size_t len, http_request_t *req) {
    if (!data || !req) return -1;
    
    char *headers_copy = malloc(len + 1);
    if (!headers_copy) return -1;
    
    memcpy(headers_copy, data, len);
    headers_copy[len] = '\0';
    
    char *line = strtok(headers_copy, "\r\n");
    while (line != NULL) {
        char *colon = strchr(line, ':');
        if (colon) {
            *colon = '\0';
            char *name = waf_trim(line);
            char *value = waf_trim(colon + 1);
            
            /* 预留扩展 - 可在此解析和验证HTTP头 */
            (void)name;
            (void)value;
        }
        
        line = strtok(NULL, "\r\n");
    }
    
    free(headers_copy);
    return 0;
}

int http_parse_body(const char *data, size_t len, http_request_t *req) {
    if (!data || !req) return -1;
    
    if (len >= MAX_BODY_SIZE) {
        len = MAX_BODY_SIZE - 1;
    }
    
    memcpy(req->body, data, len);
    req->body[len] = '\0';
    req->body_len = len;
    
    return 0;
}

int http_parse_url(const char *url, http_request_t *req) {
    if (!url || !req) return -1;
    
    char *query = strchr(url, '?');
    if (query) {
        size_t path_len = query - url;
        if (path_len >= MAX_URL_LENGTH) path_len = MAX_URL_LENGTH - 1;
        
        strncpy(req->path, url, path_len);
        req->path[path_len] = '\0';
        
        query++;
        size_t query_len = strlen(query);
        if (query_len >= MAX_URL_LENGTH) query_len = MAX_URL_LENGTH - 1;
        
        strncpy(req->query, query, query_len);
        req->query[query_len] = '\0';
    } else {
        size_t path_len = strlen(url);
        if (path_len >= MAX_URL_LENGTH) path_len = MAX_URL_LENGTH - 1;
        
        strncpy(req->path, url, path_len);
        req->path[path_len] = '\0';
        req->query[0] = '\0';
    }
    
    return 0;
}

int http_build_request(http_request_t *req, char *buffer, size_t size) {
    if (!req || !buffer || size == 0) return -1;
    
    int offset = snprintf(buffer, size, "%s %s", req->method, req->url);
    
    if (req->headers_len > 0 && (size_t)offset < size) {
        offset += snprintf(buffer + offset, size - offset, "\r\n%s", req->headers);
    }
    
    if (offset < (int)size - 4) {
        memcpy(buffer + offset, "\r\n\r\n", 4);
        offset += 4;
    }
    
    if (req->body_len > 0 && (size_t)offset < size) {
        size_t body_copy = (size_t)offset + req->body_len < size ? req->body_len : size - offset - 1;
        memcpy(buffer + offset, req->body, body_copy);
        offset += body_copy;
    }
    
    return offset;
}

int http_build_response(http_response_t *resp, char *buffer, size_t size) {
    if (!resp || !buffer || size == 0) return -1;
    
    int offset = snprintf(buffer, size, "HTTP/1.1 %d %s\r\n", 
                         resp->status_code, resp->status_message);
    
    if (resp->headers_len > 0 && (size_t)offset < size) {
        offset += snprintf(buffer + offset, size - offset, "%s", resp->headers);
    }
    
    /* headers 经 http_set_header 逐行追加且每行已带 CRLF，此处只需补一个空行；
     * 旧代码固定追加 \r\n\r\n 会多出一个空行，body 被迫前置空行且末尾丢失 2 字节 */
    if (resp->headers_len > 0) {
        if (offset < (int)size - 2) {
            memcpy(buffer + offset, "\r\n", 2);
            offset += 2;
        }
    } else if (offset < (int)size - 4) {
        memcpy(buffer + offset, "\r\n\r\n", 4);
        offset += 4;
    }

    if (resp->body_len > 0 && (size_t)offset < size) {
        size_t available = size - offset;
        size_t body_copy = resp->body_len < available ? resp->body_len : available;
        memcpy(buffer + offset, resp->body, body_copy);
        offset += body_copy;
        if (body_copy != resp->body_len) {
            resp->body_len = body_copy;
        }
    }
    
    return offset;
}

int http_send_response(int fd, http_response_t *resp) {
    if (fd < 0 || !resp) return -1;
    
    char buffer[MAX_REQUEST_SIZE];
    int len = http_build_response(resp, buffer, sizeof(buffer));
    
    if (len < 0) return -1;
    
    ssize_t sent = send(fd, buffer, (size_t)len, 0);
    return (int)sent;
}

int http_receive_request(int fd, char *buffer, size_t size, int *ssl) {
    if (fd < 0 || !buffer || size == 0) return -1;

    *ssl = 0;

    /* Read in a loop until headers + Content-Length body bytes are all
     * received. A single recv() would miss the body whenever it arrives
     * in a separate TCP segment, making POST-body inspection unreliable.
     * Client sockets are non-blocking, so EAGAIN must be waited out via
     * select() instead of aborting the read. */
    size_t total = 0;
    size_t content_length = 0;
    int headers_done = 0;
    size_t header_end_pos = 0;
    int read_till_close = 0;
    time_t first_byte_deadline = 0;
    time_t deadline = time(NULL) + 5; /* overall cap: 5 seconds */

    while (total < size - 1) {
        ssize_t received = recv(fd, buffer + total, size - 1 - total, 0);
        if (received < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (time(NULL) >= deadline) break;
                /* read-till-close 模式：1 秒内首字节未到则按无 body 处理 */
                if (read_till_close && total <= header_end_pos &&
                    time(NULL) >= first_byte_deadline) break;
                fd_set rfds;
                struct timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = 200 * 1000;
                FD_ZERO(&rfds);
                FD_SET(fd, &rfds);
                select(fd + 1, &rfds, NULL, NULL, &tv);
                continue;
            }
            return (total > 0) ? (int)total : -1;
        }
        if (received == 0) break;
        total += (size_t)received;
        buffer[total] = '\0';

        if (!headers_done) {
            char *hend = strstr(buffer, "\r\n\r\n");
            size_t hend_len = 4;
            if (!hend) {
                hend = strstr(buffer, "\n\n");
                hend_len = 2;
            }
            if (!hend) continue; /* headers still incomplete */

            headers_done = 1;
            header_end_pos = (size_t)(hend - buffer) + hend_len;
            char clbuf[32] = {0};
            int has_cl = (http_get_header_value(buffer, "Content-Length", clbuf, sizeof(clbuf)) >= 0);
            if (has_cl) {
                content_length = (size_t)strtoul(clbuf, NULL, 10);
            }
            if (content_length == 0 && has_cl) break; /* 显式 CL:0 = 无 body */
            if (content_length == 0) {
                /* 无 Content-Length 的 POST/PUT/PATCH 可能以连接关闭界定 body
                 * (blazehttp 样本即用此绕过检测)；给 1 秒窗口等首字节，
                 * 读不到就按无 body 处理，避免 keep-alive 空 POST 挂住 worker */
                if (strncmp(buffer, "POST ", 5) == 0 ||
                    strncmp(buffer, "PUT ", 4) == 0 ||
                    strncmp(buffer, "PATCH ", 6) == 0) {
                    read_till_close = 1;
                    first_byte_deadline = time(NULL) + 1;
                    if (total > header_end_pos) break; /* body 已随首包到达 */
                    continue;
                }
                break; /* no body expected */
            }

            /* Never try to buffer more than the request buffer allows */
            if (content_length > size - 1) content_length = size - 1;

            size_t header_end = header_end_pos;
            size_t body_so_far = (total > header_end) ? (total - header_end) : 0;
            if (body_so_far >= content_length) break;
        } else {
            char *hend = strstr(buffer, "\r\n\r\n");
            size_t hend_len = 4;
            if (!hend) {
                hend = strstr(buffer, "\n\n");
                hend_len = 2;
            }
            if (hend) {
                size_t header_end = (size_t)(hend - buffer) + hend_len;
                size_t body_so_far = (total > header_end) ? (total - header_end) : 0;
                if (body_so_far >= content_length) break;
            }
        }
    }

    buffer[total] = '\0';
    return (int)total;
}

/* 不分配内存的版本，用于快速查找 */
int http_get_header_value(const char *headers, const char *name, char *buf, size_t buf_size) {
    if (!headers || !name || !buf || buf_size == 0) return -1;
    
    size_t headers_len = strlen(headers);
    size_t name_len = strlen(name);
    
    for (size_t i = 0; i < headers_len; i++) {
        if (strncasecmp(headers + i, name, name_len) == 0) {
            const char *colon = headers + i + name_len;
            if (*colon == ':') {
                const char *value = colon + 1;
                while (*value == ' ' || *value == '\t') value++;
                
                const char *end = value;
                while (*end != '\r' && *end != '\n' && *end != '\0') end++;
                
                size_t value_len = end - value;
                if (value_len >= buf_size) value_len = buf_size - 1;
                
                strncpy(buf, value, value_len);
                buf[value_len] = '\0';
                return (int)value_len;
            }
        }
    }
    
    return -1;
}

const char* http_get_header(const char *headers, const char *name) {
    if (!headers || !name) return NULL;
    
    size_t headers_len = strlen(headers);
    size_t name_len = strlen(name);
    
    for (size_t i = 0; i < headers_len; i++) {
        if (strncasecmp(headers + i, name, name_len) == 0) {
            const char *colon = headers + i + name_len;
            if (*colon == ':') {
                const char *value = colon + 1;
                while (*value == ' ' || *value == '\t') value++;
                
                const char *end = value;
                while (*end != '\r' && *end != '\n' && *end != '\0') end++;
                
                size_t value_len = end - value;
                char *result = malloc(value_len + 1);
                if (result) {
                    strncpy(result, value, value_len);
                    result[value_len] = '\0';
                    return result;
                }
            }
        }
    }
    
    return NULL;
}

int http_has_header(const char *headers, const char *name) {
    return http_get_header(headers, name) != NULL;
}

int http_set_header(http_response_t *resp, const char *name, const char *value) {
    if (!resp || !name || !value) return -1;
    
    char header[512];
    snprintf(header, sizeof(header), "%s: %s\r\n", name, value);
    
    size_t header_len = strlen(header);
    if (resp->headers_len + header_len >= MAX_HEADER_SIZE) {
        return -1;
    }
    
    strcpy(resp->headers + resp->headers_len, header);
    resp->headers_len += header_len;
    resp->headers[resp->headers_len] = '\0';
    
    return 0;
}

int http_set_body(http_response_t *resp, const char *body, size_t len) {
    if (!resp || !body) return -1;
    
    if (len >= MAX_BODY_SIZE) {
        len = MAX_BODY_SIZE - 1;
    }
    
    memcpy(resp->body, body, len);
    resp->body[len] = '\0';
    resp->body_len = len;
    
    /* CL 只传数值，由 http_set_header 统一追加 CRLF；旧实现值里自带 CRLF 会
     * 多出一个空行，使之后设置的响应头（Connection 等）被浏览器当成 body，
     * keep-alive 下页面渲染异常 */
    char content_length[24];
    snprintf(content_length, sizeof(content_length), "%zu", len);
    http_set_header(resp, "Content-Length", content_length);
    
    return 0;
}

int http_set_status(http_response_t *resp, int status, const char *message) {
    if (!resp || !message) return -1;
    
    resp->status_code = status;
    strncpy(resp->status_message, message, sizeof(resp->status_message) - 1);
    resp->status_message[sizeof(resp->status_message) - 1] = '\0';
    
    return 0;
}

void http_cleanup_request(http_request_t *req) {
    if (req) {
        memset(req, 0, sizeof(http_request_t));
    }
}

void http_cleanup_response(http_response_t *resp) {
    if (resp) {
        memset(resp, 0, sizeof(http_response_t));
    }
}

/* ------------------------------------------------------------------ */
/* Keep-Alive 支持                                                     */
/* ------------------------------------------------------------------ */

int http_should_keep_alive(http_request_t *req) {
    if (!req) return 0;
    char conn[64] = {0};
    int has_conn = http_get_header_value(req->headers, "Connection", conn, sizeof(conn)) >= 0;

    /* Connection: close 永远关闭 */
    if (has_conn && strcasestr(conn, "close")) return 0;

    /* 无 Content-Length 的 POST/PUT/PATCH：body 以连接静默/关闭界定，
     * keep-alive 无法可靠确定 body 边界（接收端按 read-till-close 整体吞入），
     * 必须关闭连接，不能复用。 */
    if (strcmp(req->method, "POST") == 0 || strcmp(req->method, "PUT") == 0 ||
        strcmp(req->method, "PATCH") == 0) {
        char clbuf[32] = {0};
        if (http_get_header_value(req->headers, "Content-Length", clbuf, sizeof(clbuf)) < 0)
            return 0;
    }

    /* HTTP/1.1 默认 keep-alive；HTTP/1.0 需显式 keep-alive */
    if (strncmp(req->version, "HTTP/1.1", 8) == 0) {
        return 1;
    }
    if (has_conn && strcasestr(conn, "keep-alive")) {
        return 1;
    }
    return 0;
}

void http_set_connection_header(http_response_t *resp, int keep_alive) {
    if (!resp) return;
    http_set_header(resp, "Connection", keep_alive ? "keep-alive" : "close");
    if (keep_alive) {
        char ka[64];
        snprintf(ka, sizeof(ka), "timeout=75, max=1000");
        http_set_header(resp, "Keep-Alive", ka);
    }
}

/* 计算一个完整 HTTP 请求占用的字节数（headers + body），
 * 用于流水线场景下切分缓冲区。返回 -1 表示请求不完整。 */
static ssize_t http_request_boundary(const char *buf, size_t len) {
    if (!buf || len == 0) return -1;

    char *hend = strstr(buf, "\r\n\r\n");
    size_t hend_len = 4;
    if (!hend) {
        hend = strstr(buf, "\n\n");
        hend_len = 2;
    }
    if (!hend) return -1;  /* headers 未完成 */

    size_t header_end = (size_t)(hend - buf) + hend_len;

    char clbuf[32] = {0};
    int has_cl = (http_get_header_value(buf, "Content-Length", clbuf, sizeof(clbuf)) >= 0);
    if (!has_cl) {
        /* 无 Content-Length：GET/HEAD 等无 body，请求到 header 结束为止 */
        return (ssize_t)header_end;
    }

    size_t content_length = (size_t)strtoul(clbuf, NULL, 10);
    return (ssize_t)(header_end + content_length);
}

int http_receive_keepalive_request(int fd, char *buffer, size_t size,
                                   size_t *leftover, int timeout_sec, void *ssl) {
    if (fd < 0 || !buffer || size == 0 || !leftover) return -1;

    /* buffer 前部 [0, *leftover) 已含上一请求的流水线数据 */
    size_t total = *leftover;

    time_t deadline = time(NULL) + timeout_sec;

    while (total < size - 1) {
        ssize_t boundary = http_request_boundary(buffer, total);
        if (boundary > 0 && (size_t)boundary <= total) {
            /* 无 Content-Length 的 POST/PUT/PATCH：body 以连接静默/关闭界定
             * （blazehttp 部分样本用此法携带攻击 body；旧短连路径 read_till_close
             * 能收全检测，而 boundary 会把 body 误判为下一请求 leftover 导致漏检）。
             * 此类请求在 keep-alive 下无安全边界——继续读至 200ms 静默/EOF 后
             * 整体作为一个请求返回，并由 http_should_keep_alive 对其返回 0 关闭连接。 */
            if (strncmp(buffer, "POST ", 5) == 0 ||
                strncmp(buffer, "PUT ", 4) == 0 ||
                strncmp(buffer, "PATCH ", 6) == 0) {
                char *hend = strstr(buffer, "\r\n\r\n");
                int has_cl = 1;
                if (hend) {
                    char save = hend[4];
                    hend[4] = '\0';
                    char clbuf[32] = {0};
                    has_cl = (http_get_header_value(buffer, "Content-Length", clbuf, sizeof(clbuf)) >= 0);
                    hend[4] = save;
                }
                if (!has_cl) {
                    time_t hard_deadline = time(NULL) + 5;  /* 整体上限 5 秒 */
                    for (;;) {
                        /* 200ms 静默即认为 body 完整（发完 body 等响应的客户端
                         * 不会再发数据；持续发送的场景由 5s 硬上限兜底） */
                        fd_set rfds; struct timeval tv = {0, 200 * 1000};
                        FD_ZERO(&rfds); FD_SET(fd, &rfds);
                        if (select(fd + 1, &rfds, NULL, NULL, &tv) <= 0) break;
                        if (time(NULL) >= hard_deadline) break;
                        if (total >= size - 1) break;
                        ssize_t n;
                        if (ssl) {
                            n = SSL_read((SSL *)ssl, buffer + total, (int)(size - 1 - total));
                            if (n <= 0) {
                                int err = SSL_get_error((SSL *)ssl, (int)n);
                                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                                    continue;
                                break; /* EOF/错误：已读部分即完整请求 */
                            }
                        } else {
                            n = recv(fd, buffer + total, size - 1 - total, 0);
                            if (n < 0) {
                                if (errno == EINTR) continue;
                                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                                break;
                            }
                            if (n == 0) break; /* 对端关闭：body 结束 */
                        }
                        total += (size_t)n;
                    }
                    buffer[total] = '\0';
                    *leftover = 0;
                    return (int)total;
                }
            }
            size_t consumed = (size_t)boundary;
            size_t remain = total - consumed;
            /* 不把 leftover 前移：当前请求必须原样保留在 buffer[0..consumed)
             * 供调用方 parse；流水线数据留在 buffer[consumed..total)，
             * 由调用方在下次调用前自行归位（waf.c 循环顶部 memmove）。 */
            *leftover = remain;
            return (int)consumed;
        }

        /* 不完整，继续读。SSL 路径直接用 SSL_read（不用 waf_ssl_recv，
         * 后者会尝试填满缓冲区导致每请求多等 100ms）。 */
        ssize_t n;
        if (ssl) {
            n = SSL_read((SSL *)ssl, buffer + total, (int)(size - 1 - total));
            if (n <= 0) {
                int err = SSL_get_error((SSL *)ssl, (int)n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    if (time(NULL) >= deadline) break;
                    fd_set rfds;
                    struct timeval tv;
                    tv.tv_sec = 0;
                    tv.tv_usec = 1 * 1000;  /* 1ms 轮询，降低 keep-alive 延迟 */
                    FD_ZERO(&rfds);
                    FD_SET(fd, &rfds);
                    select(fd + 1, &rfds, NULL, NULL, &tv);
                    continue;
                }
                if (err == SSL_ERROR_ZERO_RETURN) {
                    if (total > 0) { *leftover = 0; return (int)total; }
                    return 0;
                }
                if (total > 0) { *leftover = 0; return (int)total; }
                return -1;
            }
        } else {
            n = recv(fd, buffer + total, size - 1 - total, 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (time(NULL) >= deadline) break;
                    fd_set rfds;
                    struct timeval tv;
                    tv.tv_sec = 0;
                    tv.tv_usec = 1 * 1000;  /* 1ms */
                    FD_ZERO(&rfds);
                    FD_SET(fd, &rfds);
                    select(fd + 1, &rfds, NULL, NULL, &tv);
                    continue;
                }
                return -1;
            }
            if (n == 0) {
                if (total > 0) { *leftover = 0; return (int)total; }
                return 0;
            }
        }
        total += (size_t)n;
        buffer[total] = '\0';
    }

    /* 超时或 buffer 满 */
    ssize_t boundary = http_request_boundary(buffer, total);
    if (boundary > 0 && (size_t)boundary <= total) {
        size_t consumed = (size_t)boundary;
        size_t remain = total - consumed;
        /* leftover 不前移（同上）：当前请求保持 buffer[0..consumed) 原样 */
        *leftover = remain;
        return (int)consumed;
    }

    if (total > 0) {
        *leftover = 0;
        return (int)total;
    }
    return -1;
}
