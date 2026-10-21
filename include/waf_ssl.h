#ifndef WAF_SSL_H
#define WAF_SSL_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "waf.h"

typedef struct {
    SSL_CTX *ctx;
    char cert_file[512];
    char key_file[512];
} waf_site_ssl_ctx_t;

typedef struct {
    SSL_CTX *default_ctx;
    waf_site_ssl_ctx_t *site_ctxs;
    int site_count;
    int initialized;
} waf_ssl_context_t;

int waf_ssl_init(waf_config_t *config);
void waf_ssl_cleanup(void);
void waf_ssl_request_reload(void);
void waf_ssl_try_pending_reload(waf_config_t *config);
SSL *waf_ssl_accept(int sockfd);
int waf_ssl_send(SSL *ssl, const void *buf, int len);
int waf_ssl_recv(SSL *ssl, void *buf, int len);
void waf_ssl_shutdown(SSL *ssl);

#endif /* WAF_SSL_H */
