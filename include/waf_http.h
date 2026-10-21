#ifndef WAF_HTTP_H
#define WAF_HTTP_H

#include "waf_common.h"

int http_parse_request(const char *data, size_t len, http_request_t *req);
int http_parse_headers(const char *data, size_t len, http_request_t *req);
int http_parse_body(const char *data, size_t len, http_request_t *req);
int http_parse_url(const char *url, http_request_t *req);
int http_build_request(http_request_t *req, char *buffer, size_t size);
int http_build_response(http_response_t *resp, char *buffer, size_t size);
int http_send_response(int fd, http_response_t *resp);
int http_receive_request(int fd, char *buffer, size_t size, int *ssl);

/* Keep-Alive 感知的请求读取：支持流水线（pipeline）。
 * 入参 *leftover 为上一请求未消费的字节数；函数将其前移到 buffer 开头，
 * 然后继续读取直到凑齐一个完整请求（headers + Content-Length body）。
 * 返回值 = 本请求消耗的字节数（>0 成功，0 连接关闭，-1 错误/超时）。
 * *leftover 出参 = 下一请求已就绪的字节数（流水线数据）。 */
int http_receive_keepalive_request(int fd, char *buffer, size_t size,
                                   size_t *leftover, int timeout_sec, void *ssl);

/* 判断客户端是否请求 keep-alive：HTTP/1.1 默认 keep-alive，HTTP/1.0 需显式
 * Connection: keep-alive；任何 Connection: close 都强制关闭。 */
int http_should_keep_alive(http_request_t *req);

/* 在响应头中设置 Connection 头（keep-alive 或 close）。 */
void http_set_connection_header(http_response_t *resp, int keep_alive);
int http_get_header_value(const char *headers, const char *name, char *buf, size_t buf_size);
const char* http_get_header(const char *headers, const char *name);
int http_has_header(const char *headers, const char *name);
int http_set_header(http_response_t *resp, const char *name, const char *value);
int http_set_body(http_response_t *resp, const char *body, size_t len);
int http_set_status(http_response_t *resp, int status, const char *message);
void http_cleanup_request(http_request_t *req);
void http_cleanup_response(http_response_t *resp);

#endif
