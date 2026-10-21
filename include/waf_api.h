#ifndef WAF_API_H
#define WAF_API_H

#include "waf.h"
#include <stdbool.h>

#define API_PORT 8080
#define API_MAX_RESPONSE_SIZE 65536

typedef enum {
    API_METHOD_GET,
    API_METHOD_POST,
    API_METHOD_PUT,
    API_METHOD_DELETE,
    API_METHOD_UNKNOWN
} api_method_t;

typedef struct {
    api_method_t method;
    char path[256];
    char query_string[1024];
    char body[4096];
    int content_length;
} api_request_t;

typedef struct {
    int status_code;
    char content_type[64];
    char body[API_MAX_RESPONSE_SIZE];
    int body_length;
} api_response_t;

int api_init(void);
void api_cleanup(void);
int api_process_request(int client_fd);
int api_process_request_ssl(int client_fd, void *ssl, int is_https);
int api_process_request_direct(int client_fd, void *ssl, int is_https, const char *buffer, int buffer_len);

void api_response_json(api_response_t *resp, int status_code, const char *json);
void api_response_error(api_response_t *resp, int status_code, const char *message);

#endif
