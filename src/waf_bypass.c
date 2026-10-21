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

#ifndef BYPASS_MAX_SITES
#define BYPASS_MAX_SITES 32
#endif
#ifndef BYPASS_BUFFER_SIZE
#define BYPASS_BUFFER_SIZE 8192
#endif
#ifndef BYPASS_MAX_PATH
#define BYPASS_MAX_PATH 1024
#endif

#ifdef USE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#endif

typedef struct {
    char domain[256];
    char document_root[512];
    int http_port;
    int https_port;
    int ssl_enabled;
    char cert_file[512];
    char key_file[512];
    int enabled;
} bypass_site_t;

static bypass_site_t g_bypass_sites[BYPASS_MAX_SITES];
static int g_bypass_site_count = 0;
static int g_running = 1;
static pthread_mutex_t g_sites_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifdef USE_OPENSSL
static SSL_CTX *g_ssl_ctx = NULL;
#endif

static int bypass_log(int level, const char *format, ...) {
    if (level < 1) return 0;
    
    va_list args;
    va_start(args, format);
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(stdout, "[%s] [BYPASS] ", timestamp);
    vfprintf(stdout, format, args);
    fprintf(stdout, "\n");
    fflush(stdout);
    
    va_end(args);
    return 0;
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
    if (strcmp(ext, ".pdf") == 0) return "application/pdf";
    if (strcmp(ext, ".zip") == 0) return "application/zip";
    if (strcmp(ext, ".woff") == 0) return "font/woff";
    if (strcmp(ext, ".woff2") == 0) return "font/woff2";
    if (strcmp(ext, ".ttf") == 0) return "font/ttf";
    if (strcmp(ext, ".eot") == 0) return "application/vnd.ms-fontobject";
    
    return "application/octet-stream";
}

static int is_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return S_ISDIR(st.st_mode);
    }
    return 0;
}

static void get_index_path(const char *doc_root, char *index_path, size_t size) {
    const char *index_files[] = {"index.html", "index.htm", "index.php", "index.cgi"};
    
    for (size_t i = 0; i < sizeof(index_files) / sizeof(index_files[0]); i++) {
        snprintf(index_path, size, "%s/%s", doc_root, index_files[i]);
        if (access(index_path, F_OK) == 0) {
            return;
        }
    }
    
    snprintf(index_path, size, "%s/index.html", doc_root);
}

static size_t build_http_response(int status, const char *status_msg, 
                               const char *content_type, const char *body, size_t body_len,
                               char *response, size_t response_size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char date_str[64];
    strftime(date_str, sizeof(date_str), "%a, %d %b %Y %H:%M:%S GMT", tm_info);
    
    return (size_t)snprintf(response, response_size,
        "HTTP/1.1 %d %s\r\n"
        "Date: %s\r\n"
        "Server: WAF-Bypass/1.0\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        status, status_msg, date_str, content_type, body_len);
}

static void send_error_response(int fd,
#ifdef USE_OPENSSL
                               SSL *ssl,
#else
                               void *ssl,
#endif
                               int status, const char *status_msg, const char *body) {
    char response[BYPASS_BUFFER_SIZE];
    size_t len = build_http_response(status, status_msg, "text/html", body, strlen(body), response, sizeof(response));
    strncat(response, body, sizeof(response) - len - 1);
    
#ifdef USE_OPENSSL
    if (ssl) {
        SSL_write(ssl, response, (int)strlen(response));
    } else
#endif
    {
        send(fd, response, (int)strlen(response), 0);
    }
}

static int send_static_file(int client_fd,
#ifdef USE_OPENSSL
                           SSL *ssl,
#else
                           void *ssl,
#endif
                           const char *doc_root, const char *path) {
    char full_path[BYPASS_MAX_PATH];
    char normalized_path[BYPASS_MAX_PATH];
    
    if (strlen(path) == 0 || strcmp(path, "/") == 0) {
        get_index_path(doc_root, full_path, sizeof(full_path));
    } else {
        snprintf(normalized_path, sizeof(normalized_path), "%s%s", doc_root, path);
        
        if (!is_directory(normalized_path)) {
            strncpy(full_path, normalized_path, sizeof(full_path) - 1);
        } else {
            if (path[strlen(path) - 1] != '/') {
                snprintf(full_path, sizeof(full_path), "%s/index.html", normalized_path);
            } else {
                snprintf(full_path, sizeof(full_path), "%s/index.html", normalized_path);
            }
        }
    }
    
    bypass_log(1, "Serving file: %s", full_path);
    
    if (access(full_path, F_OK) != 0) {
        send_error_response(client_fd, ssl, 404, "Not Found", 
            "<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>");
        return 404;
    }
    
    struct stat st;
    if (stat(full_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        send_error_response(client_fd, ssl, 403, "Forbidden",
            "<html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1></body></html>");
        return 403;
    }
    
    int file_fd = open(full_path, O_RDONLY);
    if (file_fd < 0) {
        send_error_response(client_fd, ssl, 403, "Forbidden",
            "<html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1></body></html>");
        return 403;
    }
    
    const char *mime_type = get_mime_type(full_path);
    
    char content_length[64];
    snprintf(content_length, sizeof(content_length), "%zu", (size_t)st.st_size);
    
    char final_header[BYPASS_BUFFER_SIZE];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char date_str[64];
    strftime(date_str, sizeof(date_str), "%a, %d %b %Y %H:%M:%S GMT", tm_info);
    
    snprintf(final_header, sizeof(final_header),
        "HTTP/1.1 200 OK\r\n"
        "Date: %s\r\n"
        "Server: WAF-Bypass/1.0\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        date_str, mime_type, content_length);
    
#ifdef USE_OPENSSL
    if (ssl) {
        SSL_write(ssl, final_header, (int)strlen(final_header));
    } else {
        send(client_fd, final_header, (int)strlen(final_header), 0);
    }
#else
    send(client_fd, final_header, (int)strlen(final_header), 0);
#endif
    
    char file_buffer[BYPASS_BUFFER_SIZE];
    ssize_t bytes_read;
    while ((bytes_read = read(file_fd, file_buffer, sizeof(file_buffer))) > 0) {
#ifdef USE_OPENSSL
        if (ssl) {
            int bytes_written = SSL_write(ssl, file_buffer, (int)bytes_read);
            if (bytes_written <= 0) break;
        } else {
            ssize_t bytes_sent = send(client_fd, file_buffer, (size_t)bytes_read, 0);
            if (bytes_sent <= 0) break;
        }
#else
        ssize_t bytes_sent = send(client_fd, file_buffer, (size_t)bytes_read, 0);
        if (bytes_sent <= 0) break;
#endif
    }
    
    close(file_fd);
    return 200;
}

static void parse_http_request(const char *data, char *method, size_t method_size,
                               char *path, size_t path_size) {
    const char *ptr = data;
    const char *end = strstr(data, " HTTP");
    
    if (end && (size_t)(end - data) < method_size) {
        size_t len = end - data;
        strncpy(method, data, len);
        method[len] = '\0';
    }
    
    const char *path_start = strchr(data, ' ');
    if (path_start) {
        path_start++;
        const char *path_end = strchr(path_start, ' ');
        if (path_end && (size_t)(path_end - path_start) < path_size) {
            size_t len = path_end - path_start;
            strncpy(path, path_start, len);
            path[len] = '\0';
        }
    }
}

static void handle_client(int client_fd,
#ifdef USE_OPENSSL
                         SSL *ssl,
#else
                         void *ssl,
#endif
                         bypass_site_t *site) {
    char buffer[BYPASS_BUFFER_SIZE];
    ssize_t bytes_received;
    
#ifdef USE_OPENSSL
    if (ssl) {
        bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    } else {
        bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    }
#else
    bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
#endif
    
    if (bytes_received <= 0) {
#ifdef USE_OPENSSL
        if (ssl) SSL_free(ssl);
#endif
        close(client_fd);
        return;
    }
    
    buffer[bytes_received] = '\0';
    
    char method[16] = {0};
    char path[BYPASS_MAX_PATH] = {0};
    parse_http_request(buffer, method, sizeof(method), path, sizeof(path));
    
    bypass_log(1, "Request: %s %s from %s:%d",
               method, path,
#ifdef USE_OPENSSL
               ssl ? "HTTPS" : "HTTP",
#else
               "HTTP",
#endif
               site ? site->domain : "unknown");
    
    if (site) {
        send_static_file(client_fd, ssl, site->document_root, path);
    } else {
        char response[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
#ifdef USE_OPENSSL
        if (ssl) {
            SSL_write(ssl, response, (int)strlen(response));
        } else {
            send(client_fd, response, (int)strlen(response), 0);
        }
#else
        send(client_fd, response, (int)strlen(response), 0);
#endif
    }
    
#ifdef USE_OPENSSL
    if (ssl) SSL_free(ssl);
#endif
    close(client_fd);
}

static int create_listening_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        bypass_log(0, "Failed to create socket: %s", strerror(errno));
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
        bypass_log(0, "Failed to bind to port %d: %s", port, strerror(errno));
        close(fd);
        return -1;
    }
    
    if (listen(fd, 10) < 0) {
        bypass_log(0, "Failed to listen on port %d: %s", port, strerror(errno));
        close(fd);
        return -1;
    }
    
    bypass_log(1, "Listening on port %d", port);
    return fd;
}

typedef struct {
    int client_fd;
#ifdef USE_OPENSSL
    SSL *ssl;
#else
    void *ssl;
#endif
    bypass_site_t *site;
} connection_args_t;

static void* handle_connection(void *arg) {
    connection_args_t *args = (connection_args_t*)arg;
    
    handle_client(args->client_fd, args->ssl, args->site);
    
    free(arg);
    return NULL;
}

static void* bypass_server_thread(void *arg) {
    bypass_site_t *site = (bypass_site_t*)arg;
    int port = site->https_port;
    
    int listen_fd = create_listening_socket(port);
    if (listen_fd < 0) {
        bypass_log(0, "Failed to start bypass server for %s on port %d", site->domain, port);
        return NULL;
    }
    
    bypass_log(1, "Bypass server started for %s on port %d (HTTPS)", site->domain, port);
    
    while (g_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (g_running) {
                bypass_log(0, "Accept failed: %s", strerror(errno));
            }
            continue;
        }
        
#ifdef USE_OPENSSL
        SSL *ssl = NULL;
        if (site->ssl_enabled && g_ssl_ctx) {
            ssl = SSL_new(g_ssl_ctx);
            if (ssl) {
                SSL_set_fd(ssl, client_fd);
                if (SSL_accept(ssl) <= 0) {
                    SSL_free(ssl);
                    ssl = NULL;
                    close(client_fd);
                    continue;
                }
            }
        }
#else
        void *ssl = NULL;
#endif
        
        connection_args_t *args = malloc(sizeof(connection_args_t));
        if (!args) {
#ifdef USE_OPENSSL
            if (ssl) SSL_free(ssl);
#endif
            close(client_fd);
            continue;
        }
        
        args->client_fd = client_fd;
        args->ssl = ssl;
        args->site = site;
        
        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_connection, args) != 0) {
            bypass_log(0, "Failed to create thread");
#ifdef USE_OPENSSL
            if (ssl) SSL_free(ssl);
#endif
            close(client_fd);
            free(args);
        } else {
            pthread_detach(thread);
        }
    }
    
    close(listen_fd);
    return NULL;
}

#ifdef USE_OPENSSL
static int init_ssl_ctx(const char *cert_file, const char *key_file) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    g_ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_ssl_ctx) {
        bypass_log(0, "Failed to create SSL context");
        return -1;
    }
    
    if (SSL_CTX_use_certificate_file(g_ssl_ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        bypass_log(0, "Failed to load certificate: %s", cert_file);
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
        return -1;
    }
    
    if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        bypass_log(0, "Failed to load private key: %s", key_file);
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
        return -1;
    }
    
    if (!SSL_CTX_check_private_key(g_ssl_ctx)) {
        bypass_log(0, "Certificate and private key do not match");
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
        return -1;
    }
    
    bypass_log(1, "SSL context initialized with cert: %s", cert_file);
    return 0;
}
#endif

static int parse_site_config(const char *filename, bypass_site_t *site) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        bypass_log(0, "Failed to open config file: %s", filename);
        return -1;
    }
    
    char section[64] = {0};
    char line[1024];
    
    memset(site, 0, sizeof(bypass_site_t));
    site->http_port = 8080;
    site->https_port = 8443;
    site->enabled = 1;
    
    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = waf_trim(line);
        
        if (*trimmed == '\0' || *trimmed == '#' || *trimmed == ';') {
            continue;
        }
        
        if (trimmed[0] == '[') {
            char *end = strchr(trimmed, ']');
            if (end) {
                *end = '\0';
                strncpy(section, trimmed + 1, sizeof(section) - 1);
            }
            continue;
        }
        
        char key[64], value[512];
        char *eq = strchr(trimmed, '=');
        if (!eq) continue;
        
        *eq = '\0';
        strncpy(key, waf_trim(trimmed), sizeof(key) - 1);
        strncpy(value, waf_trim(eq + 1), sizeof(value) - 1);
        
        if (strcmp(section, "site") == 0) {
            if (strcmp(key, "domain") == 0) {
                strncpy(site->domain, value, sizeof(site->domain) - 1);
            } else if (strcmp(key, "document_root") == 0) {
                strncpy(site->document_root, value, sizeof(site->document_root) - 1);
            } else if (strcmp(key, "backend_port") == 0) {
                int backend_port = atoi(value);
                if (backend_port != 0) {
                    fclose(fp);
                    return -1;
                }
            } else if (strcmp(key, "http_port") == 0) {
                site->http_port = atoi(value);
            } else if (strcmp(key, "https_port") == 0) {
                site->https_port = atoi(value);
            } else if (strcmp(key, "enabled") == 0) {
                site->enabled = atoi(value);
            }
        } else if (strcmp(section, "ssl") == 0) {
            if (strcmp(key, "enabled") == 0) {
                site->ssl_enabled = atoi(value);
            } else if (strcmp(key, "cert_file") == 0) {
                strncpy(site->cert_file, value, sizeof(site->cert_file) - 1);
            } else if (strcmp(key, "key_file") == 0) {
                strncpy(site->key_file, value, sizeof(site->key_file) - 1);
            }
        }
    }
    
    fclose(fp);
    
    if (site->domain[0] == '\0' || site->document_root[0] == '\0') {
        return -1;
    }
    
    return 0;
}

static int load_bypass_sites(const char *config_dir) {
    DIR *dir = opendir(config_dir);
    if (!dir) {
        bypass_log(0, "Failed to open config directory: %s", config_dir);
        return -1;
    }
    
    struct dirent *entry;
    int count = 0;
    
    while ((entry = readdir(dir)) != NULL && g_bypass_site_count < BYPASS_MAX_SITES) {
        if (entry->d_type != DT_REG) continue;
        
        size_t len = strlen(entry->d_name);
        if (len < 5) continue;
        
        if (strcmp(entry->d_name + len - 5, ".conf") != 0) continue;
        
        char filepath[1024];
        snprintf(filepath, sizeof(filepath), "%s/%s", config_dir, entry->d_name);
        
        bypass_site_t site;
        if (parse_site_config(filepath, &site) == 0 && site.enabled) {
            pthread_mutex_lock(&g_sites_mutex);
            memcpy(&g_bypass_sites[g_bypass_site_count], &site, sizeof(bypass_site_t));
            g_bypass_site_count++;
            pthread_mutex_unlock(&g_sites_mutex);
            
            count++;
            bypass_log(1, "Loaded bypass site: %s (doc_root: %s, https_port: %d)",
                      site.domain, site.document_root, site.https_port);
        }
    }
    
    closedir(dir);
    return count;
}

static void signal_handler(int sig) {
    (void)sig;
    bypass_log(1, "Received signal, shutting down...");
    g_running = 0;
}

int bypass_init(const char *config_dir) {
    if (!config_dir) {
        config_dir = "/opt/waf/config/sites-bypass";
    }
    
    bypass_log(1, "Initializing bypass module...");
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    int count = load_bypass_sites(config_dir);
    if (count < 0) {
        return -1;
    }
    
    bypass_log(1, "Loaded %d bypass sites", count);
    return count;
}

int bypass_start(void) {
    if (g_bypass_site_count == 0) {
        bypass_log(1, "No bypass sites configured");
        return 0;
    }
    
    bypass_log(1, "Starting bypass servers...");
    
    for (int i = 0; i < g_bypass_site_count; i++) {
        bypass_site_t *site = &g_bypass_sites[i];
        
        if (!site->enabled) continue;
        
        if (site->ssl_enabled && site->cert_file[0] && site->key_file[0]) {
#ifdef USE_OPENSSL
            if (!g_ssl_ctx) {
                if (init_ssl_ctx(site->cert_file, site->key_file) != 0) {
                    bypass_log(0, "Failed to initialize SSL for %s", site->domain);
                    continue;
                }
            }
            
            pthread_t thread;
            if (pthread_create(&thread, NULL, bypass_server_thread, site) != 0) {
                bypass_log(0, "Failed to create server thread for %s", site->domain);
            } else {
                pthread_detach(thread);
            }
#else
            bypass_log(0, "SSL not compiled in, cannot start HTTPS server for %s", site->domain);
#endif
        } else if (site->http_port > 0) {
            bypass_log(1, "Starting HTTP bypass server for %s on port %d",
                      site->domain, site->http_port);
        }
    }
    
    return 0;
}

void bypass_stop(void) {
    bypass_log(1, "Stopping bypass module...");
    g_running = 0;
    
#ifdef USE_OPENSSL
    if (g_ssl_ctx) {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
    }
#endif
}

int bypass_reload(const char *config_dir) {
    pthread_mutex_lock(&g_sites_mutex);
    g_bypass_site_count = 0;
    pthread_mutex_unlock(&g_sites_mutex);
    
    return load_bypass_sites(config_dir);
}

void bypass_status(void) {
    pthread_mutex_lock(&g_sites_mutex);
    bypass_log(1, "Bypass module status:");
    bypass_log(1, "  Total sites: %d", g_bypass_site_count);
    for (int i = 0; i < g_bypass_site_count; i++) {
        bypass_site_t *site = &g_bypass_sites[i];
        bypass_log(1, "  - %s: %s:%d/%s (SSL: %s, Enabled: %d)",
                   site->domain,
                   site->document_root,
                   site->https_port,
                   site->ssl_enabled ? "HTTPS" : "HTTP",
                   site->ssl_enabled ? "yes" : "no",
                   site->enabled);
    }
    pthread_mutex_unlock(&g_sites_mutex);
}
