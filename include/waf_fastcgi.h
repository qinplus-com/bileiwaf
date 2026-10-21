#ifndef WAF_FASTCGI_H
#define WAF_FASTCGI_H

#include "waf.h"

#define FCGI_VERSION_1           1

#define FCGI_BEGIN_REQUEST       1
#define FCGI_ABORT_REQUEST       2
#define FCGI_END_REQUEST         3
#define FCGI_PARAMS              4
#define FCGI_STDIN               5
#define FCGI_STDOUT              6
#define FCGI_STDERR              7
#define FCGI_DATA                8
#define FCGI_GET_VALUES          9
#define FCGI_GET_VALUES_RESULT  10
#define FCGI_UNKNOWN_TYPE        11

#define FCGI_REQUEST_COMPLETE     0
#define FCGI_CANT_MPX_CONN       1
#define FCGI_OVERLOADED         2
#define FCGI_UNKNOWN_ROLE        3

#define FCGI_KEEP_CONN           1

typedef struct {
    unsigned char version;
    unsigned char type;
    unsigned char requestIdB1;
    unsigned char requestIdB0;
    unsigned char contentLengthB1;
    unsigned char contentLengthB0;
    unsigned char paddingLength;
    unsigned char reserved;
} fcgi_header;

typedef struct {
    unsigned char roleB1;
    unsigned char roleB0;
    unsigned char flags;
    unsigned char reserved[5];
} fcgi_begin_request;

typedef struct {
    unsigned char appStatusB3;
    unsigned char appStatusB2;
    unsigned char appStatusB1;
    unsigned char appStatusB0;
    unsigned char protocolStatus;
    unsigned char reserved[5];
} fcgi_end_request_body;

typedef struct {
    fcgi_header header;
    union {
        fcgi_begin_request body;
        unsigned char content[65535];
    } data;
} fcgi_request;

int fastcgi_connect(const char *host, int port, const char *socket_path);
int fastcgi_send_request(int fd, http_request_t *req, const char *doc_root, 
                         const char *script_path);
int fastcgi_read_response(int fd, char *response, size_t max_len);
void fastcgi_close(int fd);

int fastcgi_init_php_fpm(waf_site_config_t *site);
int fastcgi_handle_request(waf_site_config_t *site, http_request_t *req, 
                          char *response, size_t max_len);

#endif