#include "waf_ssl.h"
#include "waf_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

static waf_ssl_context_t ssl_ctx = {0};
static pthread_mutex_t *ssl_locks = NULL;
static int ssl_lock_count = 0;

/* SSL 上下文热加载（SIGHUP：证书续期后无需重启即可生效）。
 * 互斥保护 ssl_ctx.site_ctxs 的读写；重载时只替换指针、不释放旧上下文，
 * 避免仍在握手中的线程访问已释放内存（UAF）。旧上下文随进程存活（泄漏可忽略）。 */
static pthread_mutex_t ssl_ctx_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t ssl_reload_pending = 0;

static void ssl_lock_callback(int mode, int type, const char *file, int line) {
    if (type >= ssl_lock_count) return;
    
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&ssl_locks[type]);
    } else {
        pthread_mutex_unlock(&ssl_locks[type]);
    }
}

static unsigned long ssl_thread_id_callback(void) {
    return (unsigned long)pthread_self();
}

static void init_ssl_locks(void) {
    ssl_lock_count = CRYPTO_num_locks();
    ssl_locks = malloc(sizeof(pthread_mutex_t) * ssl_lock_count);
    if (ssl_locks) {
        for (int i = 0; i < ssl_lock_count; i++) {
            pthread_mutex_init(&ssl_locks[i], NULL);
        }
        CRYPTO_set_id_callback(ssl_thread_id_callback);
        CRYPTO_set_locking_callback(ssl_lock_callback);
    }
}

static void cleanup_ssl_locks(void) {
    if (ssl_locks) {
        CRYPTO_set_locking_callback(NULL);
        for (int i = 0; i < ssl_lock_count; i++) {
            pthread_mutex_destroy(&ssl_locks[i]);
        }
        free(ssl_locks);
        ssl_locks = NULL;
        ssl_lock_count = 0;
    }
}

static SSL_CTX* create_ssl_context(const char *cert_file, const char *key_file) {
    const SSL_METHOD *method = TLS_server_method();
    if (!method) {
        waf_log(LOG_LEVEL_ERROR, "Failed to get TLS server method");
        return NULL;
    }

    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        waf_log(LOG_LEVEL_ERROR, "Failed to create SSL context");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_CTX_set_security_level(ctx, 0);

    if (cert_file && cert_file[0] && key_file && key_file[0]) {
        if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) <= 0) {
            waf_log(LOG_LEVEL_ERROR, "Failed to load certificate: %s", cert_file);
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
            waf_log(LOG_LEVEL_ERROR, "Failed to load private key: %s", key_file);
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        }

        if (!SSL_CTX_check_private_key(ctx)) {
            waf_log(LOG_LEVEL_ERROR, "Private key does not match certificate for %s", cert_file);
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION
                              | SSL_OP_NO_TICKET);
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5:!RC4");

    /* 启用服务器端 session 缓存：返回客户端可复用会话，跳过完整 RSA/ECDHE
     * 握手（从 ~150ms 降到 ~10ms）。cache_mode 设为 both（server cache +
     * 客户端 ticket），timeout 300s，容量 20480 条。 */
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
    SSL_CTX_sess_set_cache_size(ctx, 20480);
    SSL_CTX_set_timeout(ctx, 300);

    return ctx;
}

static int ssl_sni_callback(SSL *ssl, int *ad, void *arg) {
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    waf_config_t *config = (waf_config_t*)arg;

    if (!servername) {
        return SSL_TLSEXT_ERR_OK;
    }

    /* 去除客户端 SNI 的根尾点（"dbask.cn."），否则按域名选证书会失配 */
    char sni[256];
    strncpy(sni, servername, sizeof(sni) - 1);
    sni[sizeof(sni) - 1] = '\0';
    size_t sl = strlen(sni);
    while (sl > 0 && sni[sl - 1] == '.') sni[--sl] = '\0';
    servername = sni;

    for (int i = 0; i < config->site_count; i++) {
        waf_site_config_t *site = &config->sites[i];
        if (site->cert_file[0] && site->key_file[0]) {
            for (int j = 0; j < site->domain_count; j++) {
                if (strcmp(site->domains[j], servername) == 0) {
                    pthread_mutex_lock(&ssl_ctx_lock);
                    int found = 0;
                    for (int k = 0; k < ssl_ctx.site_count; k++) {
                        if (strcmp(ssl_ctx.site_ctxs[k].cert_file, site->cert_file) == 0) {
                            SSL_set_SSL_CTX(ssl, ssl_ctx.site_ctxs[k].ctx);
                            found = 1;
                            break;
                        }
                    }
                    if (!found) {
                        SSL_CTX *new_ctx = create_ssl_context(site->cert_file, site->key_file);
                        if (new_ctx) {
                            waf_site_ssl_ctx_t *new_site_ctx = realloc(ssl_ctx.site_ctxs,
                                sizeof(waf_site_ssl_ctx_t) * (ssl_ctx.site_count + 1));
                            if (new_site_ctx) {
                                ssl_ctx.site_ctxs = new_site_ctx;
                                ssl_ctx.site_ctxs[ssl_ctx.site_count].ctx = new_ctx;
                                strncpy(ssl_ctx.site_ctxs[ssl_ctx.site_count].cert_file,
                                    site->cert_file, sizeof(ssl_ctx.site_ctxs[ssl_ctx.site_count].cert_file) - 1);
                                strncpy(ssl_ctx.site_ctxs[ssl_ctx.site_count].key_file,
                                    site->key_file, sizeof(ssl_ctx.site_ctxs[ssl_ctx.site_count].key_file) - 1);
                                ssl_ctx.site_count++;
                                SSL_set_SSL_CTX(ssl, new_ctx);
                                waf_log(LOG_LEVEL_INFO, "SNI: Created new SSL context for %s", servername);
                            } else {
                                SSL_CTX_free(new_ctx);
                            }
                        }
                    }
                    pthread_mutex_unlock(&ssl_ctx_lock);
                    waf_log(LOG_LEVEL_DEBUG, "SNI: certificate selected for %s", servername);
                    return SSL_TLSEXT_ERR_OK;
                }
            }
        }
    }

    return SSL_TLSEXT_ERR_OK;
}

int waf_ssl_init(waf_config_t *config) {
    if (ssl_ctx.initialized) {
        return 0;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    init_ssl_locks();

    ssl_ctx.default_ctx = create_ssl_context(config->cert_file, config->key_file);
    if (!ssl_ctx.default_ctx) {
        waf_log(LOG_LEVEL_WARN, "No default SSL certificate configured");
        ssl_ctx.initialized = 0;
        return 0;
    }

    SSL_CTX_set_tlsext_servername_callback(ssl_ctx.default_ctx, ssl_sni_callback);
    SSL_CTX_set_tlsext_servername_arg(ssl_ctx.default_ctx, (void*)config);

    ssl_ctx.site_count = 0;
    ssl_ctx.site_ctxs = NULL;

    ssl_ctx.initialized = 1;
    waf_log(LOG_LEVEL_INFO, "SSL initialized with SNI support");
    return 0;
}

/* 信号处理器安全点：仅置标志（async-signal-safe，不做任何实际工作） */
void waf_ssl_request_reload(void) {
    ssl_reload_pending = 1;
}

/* 请求线程安全点：收到 SIGHUP 时重建 SSL 上下文，使证书续期后无需重启即可生效 */
void waf_ssl_try_pending_reload(waf_config_t *config) {
    if (!ssl_reload_pending) return;
    ssl_reload_pending = 0;
    if (!ssl_ctx.initialized) return;

    /* 默认上下文：用全局证书重建（旧上下文不释放，避免并发 SSL_new 引用 UAF） */
    if (config && config->cert_file[0] && config->key_file[0]) {
        SSL_CTX *nd = create_ssl_context(config->cert_file, config->key_file);
        if (nd) {
            SSL_CTX_set_tlsext_servername_callback(nd, ssl_sni_callback);
            SSL_CTX_set_tlsext_servername_arg(nd, (void*)config);
            pthread_mutex_lock(&ssl_ctx_lock);
            ssl_ctx.default_ctx = nd;   /* 旧 default_ctx 泄漏（换新不换旧，安全） */
            pthread_mutex_unlock(&ssl_ctx_lock);
        } else {
            waf_log(LOG_LEVEL_WARN, "SSL reload: rebuild default context failed, keep old");
        }
    }
    /* 站点上下文缓存清空：下次 SNI 握手按新的证书文件重建（旧上下文泄漏，安全） */
    pthread_mutex_lock(&ssl_ctx_lock);
    ssl_ctx.site_ctxs = NULL;
    ssl_ctx.site_count = 0;
    pthread_mutex_unlock(&ssl_ctx_lock);

    waf_log(LOG_LEVEL_INFO, "SSL certificate contexts reloaded on SIGHUP");
}

void waf_ssl_cleanup(void) {
    if (ssl_ctx.initialized) {
        if (ssl_ctx.default_ctx) {
            SSL_CTX_free(ssl_ctx.default_ctx);
            ssl_ctx.default_ctx = NULL;
        }
        
        if (ssl_ctx.site_ctxs) {
            for (int i = 0; i < ssl_ctx.site_count; i++) {
                if (ssl_ctx.site_ctxs[i].ctx) {
                    SSL_CTX_free(ssl_ctx.site_ctxs[i].ctx);
                }
            }
            free(ssl_ctx.site_ctxs);
            ssl_ctx.site_ctxs = NULL;
        }
        
        EVP_cleanup();
        ssl_ctx.initialized = 0;
        ssl_ctx.site_count = 0;
    }
    cleanup_ssl_locks();
}

SSL *waf_ssl_accept(int sockfd) {
    if (!ssl_ctx.initialized || !ssl_ctx.default_ctx) {
        return NULL;
    }

    SSL *ssl = SSL_new(ssl_ctx.default_ctx);
    if (!ssl) {
        waf_log(LOG_LEVEL_ERROR, "Failed to create SSL object");
        return NULL;
    }

    SSL_set_fd(ssl, sockfd);
    
    int ret;
    int attempts = 0;
    const int max_attempts = 100;
    
    while ((ret = SSL_accept(ssl)) <= 0 && attempts < max_attempts) {
        int err = SSL_get_error(ssl, ret);
        
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            attempts++;
            struct timespec ts = {0, 10000000};
            nanosleep(&ts, NULL);
            continue;
        } else if (err == SSL_ERROR_SYSCALL) {
            if (errno == 0 || errno == EAGAIN || errno == EWOULDBLOCK) {
                attempts++;
                struct timespec ts = {0, 10000000};
                nanosleep(&ts, NULL);
                continue;
            }
        }
        
        long err_code = ERR_peek_last_error_line(NULL, NULL);
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        waf_log(LOG_LEVEL_WARN, "SSL handshake failed, SSL error: %d, errno: %d, err: %s", 
                err, errno, err_buf);
        SSL_free(ssl);
        return NULL;
    }
    
    if (ret <= 0) {
        waf_log(LOG_LEVEL_WARN, "SSL handshake timeout after %d attempts", max_attempts);
        SSL_free(ssl);
        return NULL;
    }

    return ssl;
}

int waf_ssl_send(SSL *ssl, const void *buf, int len) {
    if (!ssl) return -1;
    
    int written = 0;
    int attempts = 0;
    const int max_attempts = 100;
    
    while (written < len && attempts < max_attempts) {
        int result = SSL_write(ssl, (const char *)buf + written, len - written);
        if (result <= 0) {
            int err = SSL_get_error(ssl, result);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                attempts++;
                struct timespec ts = {0, 1000000};
                nanosleep(&ts, NULL);
                continue;
            }
            if (err == SSL_ERROR_SYSCALL) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    attempts++;
                    struct timespec ts = {0, 1000000};
                    nanosleep(&ts, NULL);
                    continue;
                }
            }
            return -1;
        }
        written += result;
        attempts = 0;
    }
    
    return written;
}

int waf_ssl_recv(SSL *ssl, void *buf, int len) {
    if (!ssl) return -1;
    
    int received = 0;
    int attempts = 0;
    const int max_attempts = 100;
    
    while (received < len && attempts < max_attempts) {
        int result = SSL_read(ssl, (char *)buf + received, len - received);
        if (result <= 0) {
            int err = SSL_get_error(ssl, result);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                attempts++;
                struct timespec ts = {0, 1000000};
                nanosleep(&ts, NULL);
                continue;
            }
            if (err == SSL_ERROR_SYSCALL) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    attempts++;
                    struct timespec ts = {0, 1000000};
                    nanosleep(&ts, NULL);
                    continue;
                }
            }
            if (err == SSL_ERROR_ZERO_RETURN) {
                return received;
            }
            return received > 0 ? received : result;
        }
        received += result;
        attempts = 0;
    }
    
    return received;
}

void waf_ssl_shutdown(SSL *ssl) {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
}
