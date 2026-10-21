#ifndef WAF_PROXY_H
#define WAF_PROXY_H

#include "waf.h"

#define PROXY_PROTOCOL_V1  0x01
#define PROXY_PROTOCOL_V2  0x02

typedef struct {
    char upstream_host[256];
    int upstream_port;
    int timeout;
    int keepalive_enabled;
    int keepalive_timeout;
    int buffer_size;
    int retry_attempts;
    int load_balancing;  /* 0: round-robin, 1: least-connections, 2: ip-hash */
} proxy_config_t;

typedef struct {
    int fd;
    char host[256];
    int port;
    time_t last_used;
    int is_alive;
} proxy_connection_t;

typedef struct {
    proxy_connection_t *connections;
    int count;
    int current;
    int round_robin_counter;
} proxy_pool_t;

int proxy_init_pool(proxy_pool_t *pool, int max_connections);
void proxy_destroy_pool(proxy_pool_t *pool);
proxy_connection_t* proxy_get_connection(proxy_pool_t *pool, 
                                         const char *host, int port);
void proxy_release_connection(proxy_pool_t *pool, proxy_connection_t *conn);
int proxy_forward_request(waf_site_config_t *site, http_request_t *req, 
                         char *response, size_t max_len);
int proxy_handle_connection(waf_site_config_t *site, int client_fd, 
                           http_request_t *req);
int proxy_connect_upstream(const char *host, int port, int timeout);
int proxy_send_request(int fd, http_request_t *req);
int proxy_read_response(int fd, char *response, size_t max_len);
void proxy_close_connection(int fd);

#endif