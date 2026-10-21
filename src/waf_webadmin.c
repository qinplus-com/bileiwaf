/*
 * WAF WebAdmin Module
 * Provides independent HTTP/HTTPS service for WAF management interface
 * This module does NOT go through WAF defense
 */

#include "../include/waf.h"
#include "../include/waf_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef USE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifndef WEBADMIN_BUFFER_SIZE
#define WEBADMIN_BUFFER_SIZE 8192
#endif

// WebAdmin configuration
typedef struct {
    int http_port;
    int https_port;
    char domain[256];
    char document_root[512];
    int ssl_enabled;
    char cert_file[512];
    char key_file[512];
    char access_log[256];
    char error_log[256];
} webadmin_config_t;

static webadmin_config_t g_config = {0};

#ifdef USE_OPENSSL
static SSL_CTX *g_webadmin_ssl_ctx = NULL;
#endif

static int g_webadmin_running = 1;
static int g_webadmin_http_pid = 0;
static int g_webadmin_https_pid = 0;

static int load_webadmin_config(const char *config_file) {
    FILE *fp = fopen(config_file, "r");
    if (!fp) {
        // Use defaults if config file doesn't exist
        g_config.http_port = 8080;
        g_config.https_port = 28443;
        strcpy(g_config.domain, "demo.local");
        strcpy(g_config.document_root, "web");
        g_config.ssl_enabled = 1;
        strcpy(g_config.cert_file, "/opt/waf/certs/letsencrypt/dbask.cn/fullchain.pem");
        strcpy(g_config.key_file, "/opt/waf/certs/letsencrypt/dbask.cn/privkey.pem");
        strcpy(g_config.access_log, "logs/webadmin-access.log");
        strcpy(g_config.error_log, "logs/webadmin-error.log");
        return 0;
    }
    
    char line[1024];
    char section[64] = {0};
    
    while (fgets(line, sizeof(line), fp)) {
        // Trim whitespace
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#' || *p == ';') continue;
        
        if (p[0] == '[') {
            char *end = strchr(p, ']');
            if (end) {
                *end = '\0';
                strncpy(section, p + 1, sizeof(section) - 1);
            }
            continue;
        }
        
        char key[128], value[512];
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        strncpy(key, p, sizeof(key) - 1);
        strncpy(value, eq + 1, sizeof(value) - 1);
        
        // Trim key (remove trailing whitespace)
        int key_len = strlen(key);
        while (key_len > 0 && (key[key_len-1] == ' ' || key[key_len-1] == '\t')) {
            key[--key_len] = '\0';
        }
        
        // Trim values
        char *val_end = value + strlen(value) - 1;
        while (val_end > value && (*val_end == '\n' || *val_end == '\r' || *val_end == ' ' || *val_end == '\t')) {
            *val_end = '\0';
            val_end--;
        }
        
        if (strcmp(section, "server") == 0) {
            if (strcmp(key, "http_port") == 0) g_config.http_port = atoi(value);
            else if (strcmp(key, "https_port") == 0) g_config.https_port = atoi(value);
        } else if (strcmp(section, "site") == 0) {
            if (strcmp(key, "domain") == 0) strncpy(g_config.domain, value, sizeof(g_config.domain) - 1);
            else if (strcmp(key, "document_root") == 0) strncpy(g_config.document_root, value, sizeof(g_config.document_root) - 1);
        } else if (strcmp(section, "ssl") == 0) {
            if (strcmp(key, "enabled") == 0) g_config.ssl_enabled = atoi(value);
            else if (strcmp(key, "cert_file") == 0) strncpy(g_config.cert_file, value, sizeof(g_config.cert_file) - 1);
            else if (strcmp(key, "key_file") == 0) strncpy(g_config.key_file, value, sizeof(g_config.key_file) - 1);
        } else if (strcmp(section, "logging") == 0) {
            if (strcmp(key, "access_log") == 0) strncpy(g_config.access_log, value, sizeof(g_config.access_log) - 1);
            else if (strcmp(key, "error_log") == 0) strncpy(g_config.error_log, value, sizeof(g_config.error_log) - 1);
        }
    }
    
    fclose(fp);
    return 0;
}

static void webadmin_config_print(void) {
    printf("\n");
    printf("===========================================\n");
    printf("    WAF WebAdmin Configuration\n");
    printf("===========================================\n");
    printf("\n");
    printf("Config File: /opt/waf/config/webadmin.conf\n");
    printf("\n");
    printf("[Server]\n");
    printf("  HTTP Port:     %d\n", g_config.http_port);
    printf("  HTTPS Port:    %d\n", g_config.https_port);
    printf("\n");
    printf("[Site]\n");
    printf("  Domain:        %s\n", g_config.domain);
    printf("  Document Root: %s\n", g_config.document_root);
    printf("\n");
    printf("[SSL]\n");
    printf("  Enabled:       %s\n", g_config.ssl_enabled ? "Yes" : "No");
    printf("  Certificate:   %s\n", g_config.cert_file);
    printf("  Private Key:   %s\n", g_config.key_file);
    printf("\n");
    printf("[Logging]\n");
    printf("  Access Log:    %s\n", g_config.access_log);
    printf("  Error Log:     %s\n", g_config.error_log);
    printf("\n");
    printf("[Security]\n");
    printf("  WAF Bypass:    Yes (not protected by WAF)\n");
    printf("\n");
    printf("===========================================\n");
    printf("\n");
    printf("Access URLs:\n");
    printf("  HTTP:  http://%s:%d\n", g_config.domain, g_config.http_port);
    printf("  HTTPS: https://%s:%d\n", g_config.domain, g_config.https_port);
    printf("\n");
}

static const char* get_mime_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";
    
    if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0) return "text/html";
    if (strcmp(ext, ".css") == 0) return "text/css";
    if (strcmp(ext, ".js") == 0) return "application/javascript";
    if (strcmp(ext, ".json") == 0) return "application/json";
    if (strcmp(ext, ".xml") == 0) return "application/xml";
    if (strcmp(ext, ".txt") == 0) return "text/plain";
    if (strcmp(ext, ".png") == 0) return "image/png";
    if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, ".gif") == 0) return "image/gif";
    if (strcmp(ext, ".svg") == 0) return "image/svg+xml";
    if (strcmp(ext, ".ico") == 0) return "image/x-icon";
    if (strcmp(ext, ".woff") == 0) return "font/woff";
    if (strcmp(ext, ".woff2") == 0) return "font/woff2";
    if (strcmp(ext, ".ttf") == 0) return "font/ttf";
    
    return "application/octet-stream";
}

static void webadmin_log(int level, const char *format, ...) {
    if (level < 1) return;
    
    va_list args;
    va_start(args, format);
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(stdout, "[%s] [WEBADMIN] ", timestamp);
    vfprintf(stdout, format, args);
    fprintf(stdout, "\n");
    fflush(stdout);
    
    va_end(args);
}

static int create_webadmin_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        webadmin_log(0, "Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        webadmin_log(0, "Failed to bind to port %d: %s", port, strerror(errno));
        close(fd);
        return -1;
    }
    
    if (listen(fd, 10) < 0) {
        webadmin_log(0, "Failed to listen on port %d: %s", port, strerror(errno));
        close(fd);
        return -1;
    }
    
    return fd;
}

static void send_response(int client_fd, const char *status, const char *content_type, const char *body, size_t body_len) {
    char header[1024];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "Server: WAF-WebAdmin/1.0\r\n"
        "\r\n",
        status, content_type, body_len);
    
    send(client_fd, header, header_len, 0);
    send(client_fd, body, body_len, 0);
}

static void send_file(int client_fd, const char *filepath) {
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        const char *not_found = "404 Not Found";
        send_response(client_fd, "404 Not Found", "text/plain", not_found, strlen(not_found));
        return;
    }
    
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        const char *err = "500 Internal Server Error";
        send_response(client_fd, "500 Internal Server Error", "text/plain", err, strlen(err));
        return;
    }
    
    char *body = malloc((size_t)st.st_size);
    if (!body) {
        close(fd);
        const char *err = "500 Internal Server Error";
        send_response(client_fd, "500 Internal Server Error", "text/plain", err, strlen(err));
        return;
    }
    
    read(fd, body, (size_t)st.st_size);
    close(fd);
    
    const char *mime = get_mime_type(filepath);
    send_response(client_fd, "200 OK", mime, body, (size_t)st.st_size);
    
    free(body);
}

static void handle_http_request(int client_fd, const char *doc_root) {
    char buffer[WEBADMIN_BUFFER_SIZE];
    ssize_t received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) return;
    
    buffer[received] = '\0';
    
    // Parse HTTP request
    char method[16], path[256], version[16];
    if (sscanf(buffer, "%15s %255s %15s", method, path, version) != 3) {
        const char *bad_req = "400 Bad Request";
        send_response(client_fd, "400 Bad Request", "text/plain", bad_req, strlen(bad_req));
        return;
    }
    
    // Default to index.html
    if (strcmp(path, "/") == 0) {
        snprintf(path, sizeof(path), "/index.html");
    }
    
    // Security: prevent path traversal
    char normalized_path[512];
    snprintf(normalized_path, sizeof(normalized_path), "%s%s", doc_root, path);
    
    // Check for path traversal
    if (strstr(path, "..") != NULL) {
        const char *forbidden = "403 Forbidden";
        send_response(client_fd, "403 Forbidden", "text/plain", forbidden, strlen(forbidden));
        return;
    }
    
    send_file(client_fd, normalized_path);
}

#ifdef USE_OPENSSL
static void handle_https_request(int client_fd, SSL *ssl, const char *doc_root) {
    char buffer[WEBADMIN_BUFFER_SIZE];
    ssize_t received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (received <= 0) return;
    
    buffer[received] = '\0';
    
    // Parse HTTP request
    char method[16], path[256], version[16];
    if (sscanf(buffer, "%15s %255s %15s", method, path, version) != 3) {
        const char *bad_req = "400 Bad Request";
        send_response(client_fd, "400 Bad Request", "text/plain", bad_req, strlen(bad_req));
        return;
    }
    
    // Default to index.html
    if (strcmp(path, "/") == 0) {
        snprintf(path, sizeof(path), "/index.html");
    }
    
    // Security: prevent path traversal
    char normalized_path[512];
    snprintf(normalized_path, sizeof(normalized_path), "%s%s", doc_root, path);
    
    if (strstr(path, "..") != NULL) {
        const char *forbidden = "403 Forbidden";
        send_response(client_fd, "403 Forbidden", "text/plain", forbidden, strlen(forbidden));
        return;
    }
    
    // Send file via SSL
    int fd = open(normalized_path, O_RDONLY);
    if (fd < 0) {
        const char *not_found = "404 Not Found";
        send_response(client_fd, "404 Not Found", "text/plain", not_found, strlen(not_found));
        return;
    }
    
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        const char *err = "500 Internal Server Error";
        send_response(client_fd, "500 Internal Server Error", "text/plain", err, strlen(err));
        return;
    }
    
    char *body = malloc((size_t)st.st_size);
    if (!body) {
        close(fd);
        const char *err = "500 Internal Server Error";
        send_response(client_fd, "500 Internal Server Error", "text/plain", err, strlen(err));
        return;
    }
    
    read(fd, body, (size_t)st.st_size);
    close(fd);
    
    const char *mime = get_mime_type(normalized_path);
    
    char header[1024];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "Server: WAF-WebAdmin/1.0\r\n"
        "\r\n",
        mime, (size_t)st.st_size);
    
    SSL_write(ssl, header, header_len);
    SSL_write(ssl, body, (int)st.st_size);
    
    free(body);
}
#endif

static void* webadmin_http_server(void *arg) {
    (void)arg;
    
    int port = g_config.http_port;
    const char *doc_root = g_config.document_root;
    
    int listen_fd = create_webadmin_socket(port);
    if (listen_fd < 0) {
        webadmin_log(0, "Failed to start HTTP server on port %d", port);
        return NULL;
    }
    
    webadmin_log(1, "WebAdmin HTTP server started on port %d", port);
    
    while (g_webadmin_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (g_webadmin_running) {
                webadmin_log(0, "Accept failed: %s", strerror(errno));
            }
            continue;
        }
        
        // Handle request in child process
        pid_t pid = fork();
        if (pid == 0) {
            close(listen_fd);
            handle_http_request(client_fd, doc_root);
            close(client_fd);
            exit(0);
        } else if (pid > 0) {
            close(client_fd);
            waitpid(pid, NULL, 0);
        }
    }
    
    close(listen_fd);
    return NULL;
}

#ifdef USE_OPENSSL
static int init_webadmin_ssl(const char *cert_file, const char *key_file) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    g_webadmin_ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_webadmin_ssl_ctx) {
        webadmin_log(0, "Failed to create SSL context");
        return -1;
    }
    
    if (SSL_CTX_use_certificate_file(g_webadmin_ssl_ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        webadmin_log(0, "Failed to load certificate: %s", cert_file);
        SSL_CTX_free(g_webadmin_ssl_ctx);
        g_webadmin_ssl_ctx = NULL;
        return -1;
    }
    
    if (SSL_CTX_use_PrivateKey_file(g_webadmin_ssl_ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        webadmin_log(0, "Failed to load private key: %s", key_file);
        SSL_CTX_free(g_webadmin_ssl_ctx);
        g_webadmin_ssl_ctx = NULL;
        return -1;
    }
    
    if (!SSL_CTX_check_private_key(g_webadmin_ssl_ctx)) {
        webadmin_log(0, "Certificate and private key do not match");
        SSL_CTX_free(g_webadmin_ssl_ctx);
        g_webadmin_ssl_ctx = NULL;
        return -1;
    }
    
    webadmin_log(1, "SSL context initialized");
    return 0;
}

static void* webadmin_https_server(void *arg) {
    (void)arg;
    
    int port = g_config.https_port;
    const char *doc_root = g_config.document_root;
    const char *cert_file = "/opt/waf/certs/letsencrypt/dbask.cn/fullchain.pem";
    const char *key_file = "/opt/waf/certs/letsencrypt/dbask.cn/privkey.pem";
    
    if (init_webadmin_ssl(cert_file, key_file) != 0) {
        webadmin_log(0, "Failed to initialize SSL for HTTPS server");
        return NULL;
    }
    
    int listen_fd = create_webadmin_socket(port);
    if (listen_fd < 0) {
        webadmin_log(0, "Failed to start HTTPS server on port %d", port);
        return NULL;
    }
    
    webadmin_log(1, "WebAdmin HTTPS server started on port %d", port);
    
    while (g_webadmin_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (g_webadmin_running) {
                webadmin_log(0, "Accept failed: %s", strerror(errno));
            }
            continue;
        }
        
        SSL *ssl = SSL_new(g_webadmin_ssl_ctx);
        if (ssl) {
            SSL_set_fd(ssl, client_fd);
            if (SSL_accept(ssl) > 0) {
                // Handle request in child process
                pid_t pid = fork();
                if (pid == 0) {
                    close(listen_fd);
                    handle_https_request(client_fd, ssl, doc_root);
                    SSL_shutdown(ssl);
                    close(client_fd);
                    SSL_free(ssl);
                    exit(0);
                } else if (pid > 0) {
                    waitpid(pid, NULL, 0);
                }
            }
            SSL_free(ssl);
        }
        close(client_fd);
    }
    
    close(listen_fd);
    
    if (g_webadmin_ssl_ctx) {
        SSL_CTX_free(g_webadmin_ssl_ctx);
        g_webadmin_ssl_ctx = NULL;
    }
    
    return NULL;
}
#endif

static void webadmin_signal_handler(int sig) {
    (void)sig;
    webadmin_log(1, "Received signal, shutting down...");
    g_webadmin_running = 0;
}

// API Functions
int webadmin_init(void) {
    webadmin_log(1, "Initializing WebAdmin module...");
    
    // Load configuration
    load_webadmin_config("/opt/waf/config/webadmin.conf");
    
    signal(SIGINT, webadmin_signal_handler);
    signal(SIGTERM, webadmin_signal_handler);
    signal(SIGHUP, webadmin_signal_handler);
    
    return 0;
}

static pthread_t g_http_thread;
static pthread_t g_https_thread;
static int g_http_started = 0;
static int g_https_started = 0;

int webadmin_start(void) {
    webadmin_log(1, "Starting WebAdmin servers...");

    // Check document root
    if (access(g_config.document_root, F_OK) != 0) {
        webadmin_log(0, "Document root %s does not exist", g_config.document_root);
        return -1;
    }

    // Start HTTP server in a thread
    if (pthread_create(&g_http_thread, NULL, webadmin_http_server, NULL) != 0) {
        webadmin_log(0, "Failed to create HTTP server thread");
        return -1;
    }
    g_http_started = 1;

    // Start HTTPS server in a thread
#ifdef USE_OPENSSL
    if (pthread_create(&g_https_thread, NULL, webadmin_https_server, NULL) != 0) {
        webadmin_log(0, "Failed to create HTTPS server thread");
    } else {
        g_https_started = 1;
    }
#endif

    webadmin_log(1, "WebAdmin module started successfully");
    webadmin_log(1, "  HTTP:  port %d", g_config.http_port);
#ifdef USE_OPENSSL
    webadmin_log(1, "  HTTPS: port %d", g_config.https_port);
#endif

    // Wait for threads (blocking)
    if (g_http_started) {
        pthread_join(g_http_thread, NULL);
    }
#ifdef USE_OPENSSL
    if (g_https_started) {
        pthread_join(g_https_thread, NULL);
    }
#endif

    return 0;
}

void webadmin_stop(void) {
    webadmin_log(1, "Stopping WebAdmin module...");
    g_webadmin_running = 0;
}

void webadmin_status(void) {
    webadmin_log(1, "WebAdmin Module Status:");
    webadmin_log(1, "  Document Root: %s", g_config.document_root);
    webadmin_log(1, "  HTTP Port:  %d", g_config.http_port);
#ifdef USE_OPENSSL
    webadmin_log(1, "  HTTPS Port: %d", g_config.https_port);
#endif
    webadmin_log(1, "  Running:    %s", g_webadmin_running ? "Yes" : "No");
}

void webadmin_config(void) {
    load_webadmin_config("/opt/waf/config/webadmin.conf");
    webadmin_config_print();
}

int webadmin_restart(void) {
    webadmin_stop();
    sleep(1);
    return webadmin_start();
}
