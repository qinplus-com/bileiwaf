#include "../include/waf_proxy.h"
#include "../include/waf_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>

int proxy_init_pool(proxy_pool_t *pool, int max_connections) {
    if (!pool) return -1;
    
    pool->connections = calloc(max_connections, sizeof(proxy_connection_t));
    if (!pool->connections) {
        waf_log(LOG_LEVEL_ERROR, "Proxy: Failed to allocate connection pool");
        return -1;
    }
    
    for (int i = 0; i < max_connections; i++) {
        pool->connections[i].fd = -1;
        pool->connections[i].is_alive = 0;
    }
    
    pool->count = max_connections;
    pool->current = 0;
    pool->round_robin_counter = 0;
    
    waf_log(LOG_LEVEL_INFO, "Proxy: Initialized connection pool with %d connections", max_connections);
    return 0;
}

void proxy_destroy_pool(proxy_pool_t *pool) {
    if (!pool || !pool->connections) return;
    
    for (int i = 0; i < pool->count; i++) {
        if (pool->connections[i].fd >= 0) {
            close(pool->connections[i].fd);
        }
    }
    
    free(pool->connections);
    pool->connections = NULL;
    pool->count = 0;
}

proxy_connection_t* proxy_get_connection(proxy_pool_t *pool, 
                                         const char *host, int port) {
    if (!pool || !pool->connections || !host) return NULL;
    
    time_t now = time(NULL);
    proxy_connection_t *best_conn = NULL;
    int best_idx = -1;
    
    for (int i = 0; i < pool->count; i++) {
        proxy_connection_t *conn = &pool->connections[i];
        
        if (conn->fd >= 0 && conn->is_alive) {
            if (strcmp(conn->host, host) == 0 && conn->port == port) {
                int is_usable = 1;
                
                struct tcp_info tcpi;
                socklen_t len = sizeof(tcpi);
                if (getsockopt(conn->fd, IPPROTO_TCP, TCP_INFO, &tcpi, &len) == 0) {
                    if (tcpi.tcpi_state != TCP_ESTABLISHED) {
                        is_usable = 0;
                    }
                }
                
                if (is_usable) {
                    best_conn = conn;
                    best_idx = i;
                    break;
                } else {
                    close(conn->fd);
                    conn->fd = -1;
                    conn->is_alive = 0;
                }
            }
        } else if (conn->fd < 0 && best_idx < 0) {
            best_idx = i;
        }
    }
    
    if (best_idx < 0) {
        best_idx = pool->current;
        if (pool->connections[best_idx].fd >= 0) {
            close(pool->connections[best_idx].fd);
        }
    }
    
    proxy_connection_t *conn = &pool->connections[best_idx];
    
    if (conn->fd < 0 || !conn->is_alive) {
        int fd = proxy_connect_upstream(host, port, 30);
        if (fd < 0) {
            conn->is_alive = 0;
            return NULL;
        }
        
        conn->fd = fd;
        strncpy(conn->host, host, sizeof(conn->host) - 1);
        conn->port = port;
        conn->is_alive = 1;
    }
    
    conn->last_used = now;
    pool->current = (pool->current + 1) % pool->count;
    
    return conn;
}

void proxy_release_connection(proxy_pool_t *pool, proxy_connection_t *conn) {
    (void)pool;
    (void)conn;
}

int proxy_connect_upstream(const char *host, int port, int timeout) {
    if (!host || port <= 0) return -1;
    
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        waf_log(LOG_LEVEL_ERROR, "Proxy: Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    
    struct hostent *server = gethostbyname(host);
    if (!server) {
        waf_log(LOG_LEVEL_ERROR, "Proxy: Failed to resolve host: %s", host);
        close(fd);
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);
    addr.sin_port = htons((uint16_t)port);
    
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        waf_log(LOG_LEVEL_ERROR, "Proxy: Failed to connect to %s:%d: %s", 
                host, port, strerror(errno));
        close(fd);
        return -1;
    }
    
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    
    waf_log(LOG_LEVEL_DEBUG, "Proxy: Connected to upstream %s:%d", host, port);
    return fd;
}

int proxy_send_request(int fd, http_request_t *req) {
    if (!req) return -1;
    
    char buffer[MAX_REQUEST_SIZE];
    int len = http_build_request(req, buffer, sizeof(buffer));
    
    if (len <= 0) {
        waf_log(LOG_LEVEL_ERROR, "Proxy: Failed to build HTTP request");
        return -1;
    }
    
    ssize_t sent = 0;
    while (sent < len) {
        ssize_t s = send(fd, buffer + sent, (size_t)(len - sent), 0);
        if (s <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(10000);
                continue;
            }
            waf_log(LOG_LEVEL_ERROR, "Proxy: Failed to send request: %s", strerror(errno));
            return -1;
        }
        sent += s;
    }
    
    return 0;
}

int proxy_read_response(int fd, char *response, size_t max_len) {
    if (!response || max_len == 0) return -1;
    
    size_t total_received = 0;
    fd_set read_fds;
    struct timeval timeout;
    
    while (total_received < max_len - 1) {
        FD_ZERO(&read_fds);
        FD_SET(fd, &read_fds);
        timeout.tv_sec = 30;
        timeout.tv_usec = 0;
        
        int activity = select(fd + 1, &read_fds, NULL, NULL, &timeout);
        if (activity <= 0) {
            break;
        }
        
        ssize_t received = recv(fd, response + total_received, 
                               max_len - total_received - 1, 0);
        if (received <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            break;
        }
        
        total_received += received;
        
        char *body_start = strstr(response, "\r\n\r\n");
        if (body_start && total_received > (size_t)(body_start - response + 4)) {
            body_start += 4;
            
            char *content_length_hdr = strcasestr(response, "Content-Length:");
            if (content_length_hdr) {
                int content_length = atoi(content_length_hdr + 15);
                
                size_t header_len = body_start - response;
                size_t body_received = total_received - header_len;
                
                if (body_received >= (size_t)content_length) {
                    break;
                }
            } else {
                char *transfer_encoding = strcasestr(response, "Transfer-Encoding:");
                if (transfer_encoding && strcasestr(transfer_encoding, "chunked")) {
                    if (strstr(response, "\r\n0\r\n\r\n")) {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
    }
    
    response[total_received] = '\0';
    return (int)total_received;
}

void proxy_close_connection(int fd) {
    if (fd >= 0) {
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }
}

int proxy_forward_request(waf_site_config_t *site, http_request_t *req, 
                         char *response, size_t max_len) {
    if (!site || !req || !response) return -1;
    
    const char *upstream_host = site->runtime.upstream_host[0] ? 
                                site->runtime.upstream_host : site->backend_host;
    int upstream_port = site->runtime.upstream_port > 0 ? 
                        site->runtime.upstream_port : site->backend_port;
    int timeout = site->runtime.timeout > 0 ? site->runtime.timeout : 30;
    
    int fd = proxy_connect_upstream(upstream_host, upstream_port, timeout);
    if (fd < 0) {
        waf_log(LOG_LEVEL_ERROR, "Proxy: Failed to connect to upstream %s:%d", 
                upstream_host, upstream_port);
        return -1;
    }
    
    if (proxy_send_request(fd, req) < 0) {
        proxy_close_connection(fd);
        return -1;
    }
    
    int len = proxy_read_response(fd, response, max_len);
    proxy_close_connection(fd);
    
    if (len < 0) {
        waf_log(LOG_LEVEL_ERROR, "Proxy: Failed to read response from upstream");
        return -1;
    }
    
    return len;
}

int proxy_handle_connection(waf_site_config_t *site, int client_fd, 
                           http_request_t *req) {
    if (!site || !req) return -1;
    
    const char *upstream_host = site->runtime.upstream_host[0] ? 
                                site->runtime.upstream_host : site->backend_host;
    int upstream_port = site->runtime.upstream_port > 0 ? 
                        site->runtime.upstream_port : site->backend_port;
    int timeout = site->runtime.timeout > 0 ? site->runtime.timeout : 30;
    
    int backend_fd = proxy_connect_upstream(upstream_host, upstream_port, timeout);
    if (backend_fd < 0) {
        return -1;
    }
    
    if (proxy_send_request(backend_fd, req) < 0) {
        proxy_close_connection(backend_fd);
        return -1;
    }
    
    char buffer[MAX_REQUEST_SIZE];
    ssize_t received;
    
    while ((received = recv(backend_fd, buffer, sizeof(buffer), 0)) > 0) {
        ssize_t sent = 0;
        while (sent < received) {
            ssize_t s = send(client_fd, buffer + sent, (size_t)(received - sent), 0);
            if (s <= 0) {
                proxy_close_connection(backend_fd);
                return -1;
            }
            sent += s;
        }
    }
    
    proxy_close_connection(backend_fd);
    return 0;
}