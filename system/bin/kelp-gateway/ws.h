/* kelp-gateway ws.h - WebSocket support */
#ifndef KELP_GW_WS_H
#define KELP_GW_WS_H

#include <stdint.h>
#include <stddef.h>

#define WS_OPCODE_TEXT   0x01
#define WS_OPCODE_BINARY 0x02
#define WS_OPCODE_CLOSE  0x08
#define WS_OPCODE_PING   0x09
#define WS_OPCODE_PONG   0x0A

char *ws_compute_accept_key(const char *client_key);
int ws_send_frame(int fd, uint8_t opcode, const void *data, size_t len);
int ws_read_frame(int fd, uint8_t *opcode, uint8_t **payload, size_t *payload_len);
void ws_handle_connection(int client_fd);
int ws_listener_create(const char *addr, int port);

#endif
