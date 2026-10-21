#include "../include/waf_fastcgi.h"
#include "../include/waf_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/un.h>

static unsigned short fcgi_get_request_id(fcgi_header *header) {
    return (header->requestIdB0 << 8) | header->requestIdB1;
}

static void fcgi_set_request_id(fcgi_header *header, unsigned short id) {
    header->requestIdB1 = (id >> 8) & 0xFF;
    header->requestIdB0 = id & 0xFF;
}

static unsigned short fcgi_get_content_length(fcgi_header *header) {
    return (header->contentLengthB0 << 8) | header->contentLengthB1;
}

static void fcgi_set_content_length(fcgi_header *header, unsigned short len) {
    header->contentLengthB1 = (len >> 8) & 0xFF;
    header->contentLengthB0 = len & 0xFF;
}

static void fcgi_create_header(unsigned char type, unsigned short request_id,
                                unsigned short content_length, unsigned char padding) {
}

int fastcgi_connect(const char *host, int port, const char *socket_path) {
    int fd;
    
    if (socket_path && socket_path[0]) {
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            waf_log(LOG_LEVEL_ERROR, "Failed to create Unix socket: %s", strerror(errno));
            return -1;
        }
        
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
        
        if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            waf_log(LOG_LEVEL_ERROR, "Failed to connect to Unix socket %s: %s", 
                    socket_path, strerror(errno));
            close(fd);
            return -1;
        }
        
        waf_log(LOG_LEVEL_INFO, "Connected to PHP-FPM via Unix socket: %s", socket_path);
        return fd;
    }
    
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        waf_log(LOG_LEVEL_ERROR, "Failed to create TCP socket: %s", strerror(errno));
        return -1;
    }
    
    struct hostent *server = gethostbyname(host);
    if (server == NULL) {
        waf_log(LOG_LEVEL_ERROR, "Failed to resolve host: %s", host);
        close(fd);
        return -1;
    }
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons((uint16_t)port);
    
    if (connect(fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        waf_log(LOG_LEVEL_ERROR, "Failed to connect to PHP-FPM %s:%d: %s", 
                host, port, strerror(errno));
        close(fd);
        return -1;
    }
    
    waf_log(LOG_LEVEL_INFO, "Connected to PHP-FPM via TCP: %s:%d", host, port);
    return fd;
}

int fastcgi_begin_request(int fd, unsigned short request_id, unsigned short role, unsigned char flags) {
    fcgi_header header;
    fcgi_begin_request begin_req;
    
    memset(&header, 0, sizeof(header));
    header.version = FCGI_VERSION_1;
    header.type = FCGI_BEGIN_REQUEST;
    fcgi_set_request_id(&header, request_id);
    header.contentLengthB1 = 0;
    header.contentLengthB0 = sizeof(fcgi_begin_request);
    header.paddingLength = 0;
    header.reserved = 0;
    
    memset(&begin_req, 0, sizeof(begin_req));
    begin_req.roleB1 = (role >> 8) & 0xFF;
    begin_req.roleB0 = role & 0xFF;
    begin_req.flags = flags;
    
    if (send(fd, &header, sizeof(header), 0) != sizeof(header)) {
        waf_log(LOG_LEVEL_ERROR, "Failed to send FastCGI begin request header");
        return -1;
    }
    
    if (send(fd, &begin_req, sizeof(begin_req), 0) != sizeof(begin_req)) {
        waf_log(LOG_LEVEL_ERROR, "Failed to send FastCGI begin request body");
        return -1;
    }
    
    return 0;
}

int fastcgi_send_params(int fd, unsigned short request_id, http_request_t *req,
                        const char *doc_root, const char *script_path) {
    char params[8192];
    int offset = 0;
    
    char script_filename[1024];
    if (script_path && script_path[0]) {
        snprintf(script_filename, sizeof(script_filename), "%s%s", doc_root, script_path);
    } else {
        snprintf(script_filename, sizeof(script_filename), "%s/index.php", doc_root);
    }
    
    #define FCGI_PARAM(name, value) do { \
        int name_len = strlen(name); \
        int value_len = strlen(value); \
        if (name_len < 128) params[offset++] = name_len; \
        else { params[offset++] = (name_len >> 24) | 0x80; params[offset++] = (name_len >> 16) & 0xFF; params[offset++] = (name_len >> 8) & 0xFF; params[offset++] = name_len & 0xFF; } \
        if (value_len < 128) params[offset++] = value_len; \
        else { params[offset++] = (value_len >> 24) | 0x80; params[offset++] = (value_len >> 16) & 0xFF; params[offset++] = (value_len >> 8) & 0xFF; params[offset++] = value_len & 0xFF; } \
        memcpy(params + offset, name, name_len); offset += name_len; \
        memcpy(params + offset, value, value_len); offset += value_len; \
    } while(0)
    
    FCGI_PARAM("REQUEST_METHOD", req->method);
    FCGI_PARAM("SCRIPT_NAME", script_path ? script_path : "/index.php");
    FCGI_PARAM("SCRIPT_FILENAME", script_filename);
    FCGI_PARAM("REQUEST_URI", req->url);
    FCGI_PARAM("DOCUMENT_URI", script_path ? script_path : "/index.php");
    FCGI_PARAM("DOCUMENT_ROOT", doc_root);
    FCGI_PARAM("SERVER_PROTOCOL", "HTTP/1.1");
    FCGI_PARAM("SERVER_SOFTWARE", "WAF/1.0");
    
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", req->client_port);
    FCGI_PARAM("SERVER_PORT", port_str);
    FCGI_PARAM("REMOTE_ADDR", req->client_ip);
    
    if (req->query && req->query[0]) {
        FCGI_PARAM("QUERY_STRING", req->query);
    }
    
    if (req->headers) {
        char host_value[256] = {0};
        char ua_value[512] = {0};
        char accept_value[256] = {0};
        char accept_lang[256] = {0};
        char accept_enc[256] = {0};
        char content_type[128] = {0};
        char content_len[32] = {0};
        char cookie[1024] = {0};
        
        const char *headers = req->headers;
        char *header_end = strstr(headers, "\r\n\r\n");
        if (header_end) {
            size_t header_len = header_end - headers;
            char *temp_headers = malloc(header_len + 1);
            memcpy(temp_headers, headers, header_len);
            temp_headers[header_len] = '\0';
            
            char *line = strtok(temp_headers, "\r\n");
            while (line) {
                char *colon = strchr(line, ':');
                if (colon) {
                    *colon = '\0';
                    char *name = line;
                    char *value = colon + 1;
                    while (*value == ' ') value++;
                    
                    if (strcasecmp(name, "Host") == 0) strncpy(host_value, value, sizeof(host_value) - 1);
                    else if (strcasecmp(name, "User-Agent") == 0) strncpy(ua_value, value, sizeof(ua_value) - 1);
                    else if (strcasecmp(name, "Accept") == 0) strncpy(accept_value, value, sizeof(accept_value) - 1);
                    else if (strcasecmp(name, "Accept-Language") == 0) strncpy(accept_lang, value, sizeof(accept_lang) - 1);
                    else if (strcasecmp(name, "Accept-Encoding") == 0) strncpy(accept_enc, value, sizeof(accept_enc) - 1);
                    else if (strcasecmp(name, "Content-Type") == 0) strncpy(content_type, value, sizeof(content_type) - 1);
                    else if (strcasecmp(name, "Content-Length") == 0) strncpy(content_len, value, sizeof(content_len) - 1);
                    else if (strcasecmp(name, "Cookie") == 0) strncpy(cookie, value, sizeof(cookie) - 1);
                }
                line = strtok(NULL, "\r\n");
            }
            free(temp_headers);
        }
        
        if (host_value[0]) FCGI_PARAM("HTTP_HOST", host_value);
        if (ua_value[0]) FCGI_PARAM("HTTP_USER_AGENT", ua_value);
        if (accept_value[0]) FCGI_PARAM("HTTP_ACCEPT", accept_value);
        if (accept_lang[0]) FCGI_PARAM("HTTP_ACCEPT_LANGUAGE", accept_lang);
        if (accept_enc[0]) FCGI_PARAM("HTTP_ACCEPT_ENCODING", accept_enc);
        if (content_type[0]) FCGI_PARAM("CONTENT_TYPE", content_type);
        if (content_len[0]) FCGI_PARAM("CONTENT_LENGTH", content_len);
        if (cookie[0]) FCGI_PARAM("HTTP_COOKIE", cookie);
    }
    
    #undef FCGI_PARAM
    
    fcgi_header header;
    memset(&header, 0, sizeof(header));
    header.version = FCGI_VERSION_1;
    header.type = FCGI_PARAMS;
    fcgi_set_request_id(&header, request_id);
    fcgi_set_content_length(&header, (unsigned short)offset);
    header.paddingLength = 0;
    
    if (send(fd, &header, sizeof(header), 0) != sizeof(header)) {
        waf_log(LOG_LEVEL_ERROR, "Failed to send FastCGI params header");
        return -1;
    }
    
    if (send(fd, params, offset, 0) != offset) {
        waf_log(LOG_LEVEL_ERROR, "Failed to send FastCGI params");
        return -1;
    }
    
    memset(&header, 0, sizeof(header));
    header.version = FCGI_VERSION_1;
    header.type = FCGI_PARAMS;
    fcgi_set_request_id(&header, request_id);
    header.contentLengthB1 = 0;
    header.contentLengthB0 = 0;
    header.paddingLength = 0;
    
    if (send(fd, &header, sizeof(header), 0) != sizeof(header)) {
        waf_log(LOG_LEVEL_ERROR, "Failed to send FastCGI params end marker");
        return -1;
    }
    
    return 0;
}

int fastcgi_send_stdin(int fd, unsigned short request_id, const char *body, size_t body_len) {
    if (!body || body_len == 0) {
        fcgi_header header;
        memset(&header, 0, sizeof(header));
        header.version = FCGI_VERSION_1;
        header.type = FCGI_STDIN;
        fcgi_set_request_id(&header, request_id);
        header.contentLengthB1 = 0;
        header.contentLengthB0 = 0;
        header.paddingLength = 0;
        return send(fd, &header, sizeof(header), 0);
    }
    
    size_t sent = 0;
    while (sent < body_len) {
        size_t chunk = body_len - sent;
        if (chunk > 65535) chunk = 65535;
        
        fcgi_header header;
        memset(&header, 0, sizeof(header));
        header.version = FCGI_VERSION_1;
        header.type = FCGI_STDIN;
        fcgi_set_request_id(&header, request_id);
        fcgi_set_content_length(&header, (unsigned short)chunk);
        header.paddingLength = 0;
        
        if (send(fd, &header, sizeof(header), 0) != sizeof(header)) {
            return -1;
        }
        
        if (send(fd, body + sent, chunk, 0) != (ssize_t)chunk) {
            return -1;
        }
        
        sent += chunk;
    }
    
    fcgi_header header;
    memset(&header, 0, sizeof(header));
    header.version = FCGI_VERSION_1;
    header.type = FCGI_STDIN;
    fcgi_set_request_id(&header, request_id);
    header.contentLengthB1 = 0;
    header.contentLengthB0 = 0;
    header.paddingLength = 0;
    return send(fd, &header, sizeof(header), 0);
}

int fastcgi_read_response(int fd, char *response, size_t max_len) {
    size_t total_received = 0;
    unsigned short current_request_id = 0;
    
    while (total_received < max_len - 1) {
        fcgi_header header;
        int received = recv(fd, &header, sizeof(header), 0);
        
        if (received <= 0) {
            break;
        }
        
        if (received < sizeof(header)) {
            break;
        }
        
        unsigned short content_length = fcgi_get_content_length(&header);
        unsigned short request_id = fcgi_get_request_id(&header);
        
        if (content_length == 0) {
            continue;
        }
        
        char content[65536];
        size_t received_content = 0;
        while (received_content < content_length) {
            int r = recv(fd, content + received_content, content_length - received_content, 0);
            if (r <= 0) break;
            received_content += r;
        }
        
        if (received_content < content_length) {
            break;
        }
        
        if (header.type == FCGI_STDOUT) {
            size_t copy_len = content_length;
            if (total_received + copy_len > max_len - 1) {
                copy_len = max_len - total_received - 1;
            }
            memcpy(response + total_received, content, copy_len);
            total_received += copy_len;
        }
        else if (header.type == FCGI_STDERR) {
            content[received_content] = '\0';
            waf_log(LOG_LEVEL_WARN, "PHP-FPM stderr: %s", content);
        }
        else if (header.type == FCGI_END_REQUEST) {
            break;
        }
        
        if (header.paddingLength > 0) {
            char padding[256];
            recv(fd, padding, header.paddingLength, 0);
        }
    }
    
    response[total_received] = '\0';
    return total_received;
}

void fastcgi_close(int fd) {
    if (fd >= 0) {
        close(fd);
    }
}

int fastcgi_send_request(int fd, http_request_t *req, const char *doc_root, 
                         const char *script_path) {
    unsigned short request_id = 1;
    
    if (fastcgi_begin_request(fd, request_id, 1, FCGI_KEEP_CONN) < 0) {
        return -1;
    }
    
    if (fastcgi_send_params(fd, request_id, req, doc_root, script_path) < 0) {
        return -1;
    }
    
    if (req->body && req->body_len > 0) {
        if (fastcgi_send_stdin(fd, request_id, req->body, req->body_len) < 0) {
            return -1;
        }
    } else {
        fastcgi_send_stdin(fd, request_id, NULL, 0);
    }
    
    return request_id;
}

int fastcgi_init_php_fpm(waf_site_config_t *site) {
    if (!site) return -1;
    
    if (site->runtime.php_fpm.socket_path[0]) {
        waf_log(LOG_LEVEL_INFO, "PHP-FPM configured with Unix socket: %s", 
                site->runtime.php_fpm.socket_path);
    } else if (site->runtime.php_fpm.host[0]) {
        waf_log(LOG_LEVEL_INFO, "PHP-FPM configured with TCP: %s:%d", 
                site->runtime.php_fpm.host, site->runtime.php_fpm.port);
    } else {
        strcpy(site->runtime.php_fpm.socket_path, "/var/run/php-fpm/php-fpm.sock");
        waf_log(LOG_LEVEL_INFO, "PHP-FPM using default Unix socket: %s", 
                site->runtime.php_fpm.socket_path);
    }
    
    if (!site->runtime.php_fpm.document_root[0] && site->document_root[0]) {
        strncpy(site->runtime.php_fpm.document_root, site->document_root, 
                sizeof(site->runtime.php_fpm.document_root) - 1);
    }
    
    return 0;
}

int fastcgi_handle_request(waf_site_config_t *site, http_request_t *req, 
                          char *response, size_t max_len) {
    if (!site || !req || !response) {
        return -1;
    }
    
    const char *script_path = req->path && strlen(req->path) > 0 ? req->path : "/index.php";
    const char *doc_root = site->runtime.php_fpm.document_root[0] ? 
                           site->runtime.php_fpm.document_root : site->document_root;
    
    int fd = fastcgi_connect(site->runtime.php_fpm.host, site->runtime.php_fpm.port,
                            site->runtime.php_fpm.socket_path);
    if (fd < 0) {
        waf_log(LOG_LEVEL_ERROR, "Failed to connect to PHP-FPM");
        return -1;
    }
    
    if (fastcgi_send_request(fd, req, doc_root, script_path) < 0) {
        fastcgi_close(fd);
        return -1;
    }
    
    int len = fastcgi_read_response(fd, response, max_len);
    fastcgi_close(fd);
    
    return len;
}