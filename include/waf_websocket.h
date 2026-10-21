#ifndef WAF_WEBSOCKET_H
#define WAF_WEBSOCKET_H

#include "waf.h"

#define WS_OPCODE_CONTINUATION  0x0
#define WS_OPCODE_TEXT           0x1
#define WS_OPCODE_BINARY         0x2
#define WS_OPCODE_CLOSE          0x8
#define WS_OPCODE_PING           0x9
#define WS_OPCODE_PONG           0xA

#define WS_FRAME_FIN             0x80
#define WS_FRAME_MASK            0x80
#define WS_FRAME_OPCODE_MASK     0x0F
#define WS_FRAME_LENGTH_MASK     0x7F

typedef struct {
    unsigned char opcode;
    unsigned char fin;
    unsigned char masked;
    uint64_t payload_length;
    char masking_key[4];
    char *payload;
} ws_frame_t;

typedef struct {
    int fd;
    char sec_websocket_key[64];
    time_t connection_time;
    char client_ip[MAX_IP_LENGTH];
    int client_port;
} ws_connection_t;

int ws_handshake(int client_fd, const char *host_header, const char *sec_websocket_key);
int ws_send_frame(int fd, unsigned char opcode, const char *data, size_t len);
int ws_recv_frame(int fd, ws_frame_t *frame);
void ws_free_frame(ws_frame_t *frame);
int ws_proxy_request(waf_site_config_t *site, int client_fd, http_request_t *req);
int ws_handle_upgrade(int client_fd, const char *host_header, const char *sec_websocket_key,
                     const char *sec_websocket_protocol, const char *sec_websocket_version);
char* ws_generate_accept_key(const char *key);

#endif