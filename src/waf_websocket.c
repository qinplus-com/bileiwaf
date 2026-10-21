#include "../include/waf_websocket.h"
#include "../include/waf_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

static const char *WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

char* ws_generate_accept_key(const char *key) {
    if (!key) return NULL;
    
    char combined[256];
    snprintf(combined, sizeof(combined), "%s%s", key, WS_GUID);
    
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)combined, strlen(combined), hash);
    
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    
    BIO_write(bio, hash, SHA_DIGEST_LENGTH);
    BIO_flush(bio);
    
    BIO_get_mem_ptr(bio, &buffer_ptr);
    
    char *result = malloc(buffer_ptr->length + 1);
    memcpy(result, buffer_ptr->data, buffer_ptr->length);
    result[buffer_ptr->length] = '\0';
    
    for (char *p = result; *p; p++) {
        if (*p == '\n' || *p == '\r') *p = '\0';
    }
    
    BIO_free_all(bio);
    
    return result;
}

int ws_handshake(int client_fd, const char *host_header, const char *sec_websocket_key) {
    if (!sec_websocket_key) {
        waf_log(LOG_LEVEL_ERROR, "WebSocket: Missing Sec-WebSocket-Key");
        return -1;
    }
    
    char *accept_key = ws_generate_accept_key(sec_websocket_key);
    if (!accept_key) {
        waf_log(LOG_LEVEL_ERROR, "WebSocket: Failed to generate accept key");
        return -1;
    }
    
    char response[512];
    int len = snprintf(response, sizeof(response),
                      "HTTP/1.1 101 Switching Protocols\r\n"
                      "Upgrade: websocket\r\n"
                      "Connection: Upgrade\r\n"
                      "Sec-WebSocket-Accept: %s\r\n"
                      "Sec-WebSocket-Version: 13\r\n"
                      "\r\n",
                      accept_key);
    
    free(accept_key);
    
    if (send(client_fd, response, len, 0) != len) {
        waf_log(LOG_LEVEL_ERROR, "WebSocket: Failed to send handshake response");
        return -1;
    }
    
    waf_log(LOG_LEVEL_INFO, "WebSocket: Handshake completed successfully");
    return 0;
}

int ws_send_frame(int fd, unsigned char opcode, const char *data, size_t len) {
    if (!data || len == 0) {
        unsigned char frame[2] = {WS_FRAME_FIN | opcode, 0};
        return send(fd, frame, 2, 0);
    }
    
    unsigned char header[14];
    int header_len = 2;
    
    header[0] = WS_FRAME_FIN | (opcode & WS_FRAME_OPCODE_MASK);
    
    if (len < 126) {
        header[1] = (unsigned char)len;
    } else if (len < 65536) {
        header[1] = 126;
        header[2] = (len >> 8) & 0xFF;
        header[3] = len & 0xFF;
        header_len = 4;
    } else {
        header[1] = 127;
        header[2] = 0;
        header[3] = 0;
        header[4] = 0;
        header[5] = 0;
        header[6] = (len >> 24) & 0xFF;
        header[7] = (len >> 16) & 0xFF;
        header[8] = (len >> 8) & 0xFF;
        header[9] = len & 0xFF;
        header_len = 10;
    }
    
    if (send(fd, header, header_len, 0) != header_len) {
        return -1;
    }
    
    size_t sent = 0;
    while (sent < len) {
        size_t chunk = len - sent;
        if (chunk > 65535) chunk = 65535;
        
        ssize_t s = send(fd, data + sent, chunk, 0);
        if (s <= 0) return -1;
        sent += s;
    }
    
    return 0;
}

int ws_recv_frame(int fd, ws_frame_t *frame) {
    if (!frame) return -1;
    
    memset(frame, 0, sizeof(ws_frame_t));
    
    unsigned char header[2];
    int received = recv(fd, header, 2, 0);
    if (received != 2) {
        return -1;
    }
    
    frame->fin = (header[0] & WS_FRAME_FIN) != 0;
    frame->opcode = header[0] & WS_FRAME_OPCODE_MASK;
    frame->masked = (header[1] & WS_FRAME_MASK) != 0;
    frame->payload_length = header[1] & WS_FRAME_LENGTH_MASK;
    
    if (frame->payload_length == 126) {
        unsigned char len_buf[2];
        if (recv(fd, len_buf, 2, 0) != 2) return -1;
        frame->payload_length = (len_buf[0] << 8) | len_buf[1];
    } else if (frame->payload_length == 127) {
        unsigned char len_buf[8];
        if (recv(fd, len_buf, 8, 0) != 8) return -1;
        frame->payload_length = 0;
        for (int i = 0; i < 8; i++) {
            frame->payload_length = (frame->payload_length << 8) | len_buf[i];
        }
    }
    
    if (frame->masked) {
        if (recv(fd, (unsigned char*)frame->masking_key, 4, 0) != 4) {
            return -1;
        }
    }
    
    if (frame->payload_length > 0 && frame->payload_length < 65536) {
        frame->payload = malloc((size_t)frame->payload_length + 1);
        if (!frame->payload) return -1;
        
        size_t received_payload = 0;
        while (received_payload < frame->payload_length) {
            ssize_t r = recv(fd, frame->payload + received_payload, 
                           (size_t)(frame->payload_length - received_payload), 0);
            if (r <= 0) {
                free(frame->payload);
                frame->payload = NULL;
                return -1;
            }
            received_payload += r;
        }
        frame->payload[frame->payload_length] = '\0';
        
        if (frame->masked) {
            for (size_t i = 0; i < frame->payload_length; i++) {
                frame->payload[i] ^= frame->masking_key[i % 4];
            }
        }
    }
    
    return 0;
}

void ws_free_frame(ws_frame_t *frame) {
    if (frame && frame->payload) {
        free(frame->payload);
        frame->payload = NULL;
    }
}

int ws_handle_upgrade(int client_fd, const char *host_header, const char *sec_websocket_key,
                     const char *sec_websocket_protocol, const char *sec_websocket_version) {
    (void)host_header;
    (void)sec_websocket_protocol;
    (void)sec_websocket_version;
    
    return ws_handshake(client_fd, host_header, sec_websocket_key);
}

int ws_proxy_request(waf_site_config_t *site, int client_fd, http_request_t *req) {
    if (!site || !req) return -1;
    
    char sec_websocket_key[256] = {0};
    char sec_websocket_protocol[256] = {0};
    char sec_websocket_version[32] = {0};
    char host_header[256] = {0};
    
    if (req->headers) {
        char *headers_copy = strdup(req->headers);
        if (headers_copy) {
            char *line = strtok(headers_copy, "\r\n");
            while (line) {
                char *colon = strchr(line, ':');
                if (colon) {
                    *colon = '\0';
                    char *name = line;
                    char *value = colon + 1;
                    while (*value == ' ') value++;
                    
                    if (strcasecmp(name, "Sec-WebSocket-Key") == 0) {
                        strncpy(sec_websocket_key, value, sizeof(sec_websocket_key) - 1);
                    } else if (strcasecmp(name, "Sec-WebSocket-Protocol") == 0) {
                        strncpy(sec_websocket_protocol, value, sizeof(sec_websocket_protocol) - 1);
                    } else if (strcasecmp(name, "Sec-WebSocket-Version") == 0) {
                        strncpy(sec_websocket_version, value, sizeof(sec_websocket_version) - 1);
                    } else if (strcasecmp(name, "Host") == 0) {
                        strncpy(host_header, value, sizeof(host_header) - 1);
                    }
                }
                line = strtok(NULL, "\r\n");
            }
            free(headers_copy);
        }
    }
    
    if (ws_handle_upgrade(client_fd, host_header, sec_websocket_key, 
                         sec_websocket_protocol, sec_websocket_version) < 0) {
        return -1;
    }
    
    int backend_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (backend_fd < 0) {
        waf_log(LOG_LEVEL_ERROR, "WebSocket: Failed to create backend socket");
        return -1;
    }
    
    struct sockaddr_in backend_addr;
    memset(&backend_addr, 0, sizeof(backend_addr));
    backend_addr.sin_family = AF_INET;
    
    const char *backend_host = site->runtime.upstream_host[0] ? 
                                site->runtime.upstream_host : site->backend_host;
    int backend_port = site->runtime.upstream_port > 0 ? 
                       site->runtime.upstream_port : site->backend_port;
    
    struct hostent *server = gethostbyname(backend_host);
    if (!server) {
        waf_log(LOG_LEVEL_ERROR, "WebSocket: Failed to resolve backend host: %s", backend_host);
        close(backend_fd);
        return -1;
    }
    
    memcpy(&backend_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    backend_addr.sin_port = htons((uint16_t)backend_port);
    
    if (connect(backend_fd, (struct sockaddr*)&backend_addr, sizeof(backend_addr)) < 0) {
        waf_log(LOG_LEVEL_ERROR, "WebSocket: Failed to connect to backend %s:%d", 
                backend_host, backend_port);
        close(backend_fd);
        return -1;
    }
    
    fd_set read_fds;
    struct timeval timeout;
    
    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(client_fd, &read_fds);
        FD_SET(backend_fd, &read_fds);
        
        timeout.tv_sec = 300;
        timeout.tv_usec = 0;
        
        int max_fd = client_fd > backend_fd ? client_fd : backend_fd;
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (activity <= 0) {
            break;
        }
        
        if (FD_ISSET(client_fd, &read_fds)) {
            ws_frame_t client_frame;
            if (ws_recv_frame(client_fd, &client_frame) < 0) {
                break;
            }
            
            if (client_frame.opcode == WS_OPCODE_CLOSE) {
                ws_free_frame(&client_frame);
                ws_send_frame(backend_fd, WS_OPCODE_CLOSE, NULL, 0);
                break;
            }
            
            if (client_frame.opcode == WS_OPCODE_TEXT || 
                client_frame.opcode == WS_OPCODE_BINARY) {
                ws_send_frame(backend_fd, client_frame.opcode, 
                             client_frame.payload, (size_t)client_frame.payload_length);
            } else if (client_frame.opcode == WS_OPCODE_PING) {
                ws_send_frame(backend_fd, WS_OPCODE_PONG, 
                             client_frame.payload, (size_t)client_frame.payload_length);
            }
            
            ws_free_frame(&client_frame);
        }
        
        if (FD_ISSET(backend_fd, &read_fds)) {
            char buffer[65536];
            ssize_t received = recv(backend_fd, buffer, sizeof(buffer), 0);
            
            if (received <= 0) {
                break;
            }
            
            ws_send_frame(client_fd, WS_OPCODE_BINARY, buffer, (size_t)received);
        }
    }
    
    close(backend_fd);
    return 0;
}