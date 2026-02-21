/* kelp-gateway ws.c - WebSocket support */
#include "ws.h"
#include <kelp/kelp.h>
#include <kelp/config.h>
#include <cjson/cJSON.h>
#include <openssl/evp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_MAX_FRAME (1*1024*1024)

char *ws_compute_accept_key(const char *ck)
{
    if (!ck) return NULL;
    size_t kl = strlen(ck), gl = strlen(WS_GUID);
    char *cat = malloc(kl + gl + 1);
    if (!cat) return NULL;
    memcpy(cat, ck, kl);
    memcpy(cat + kl, WS_GUID, gl);
    cat[kl + gl] = 0;
    uint8_t dig[20];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { free(cat); return NULL; }
    unsigned int dl = 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) == 1
          && EVP_DigestUpdate(ctx, cat, kl + gl) == 1
          && EVP_DigestFinal_ex(ctx, dig, &dl) == 1;
    EVP_MD_CTX_free(ctx); free(cat);
    if (!ok) return NULL;
    return kelp_base64_encode(dig, (size_t)dl);
}


int ws_send_frame(int fd, uint8_t op,
    const void *data, size_t len) {
    uint8_t h[10]; size_t hl = 0;
    h[0] = 0x80 | (op & 0x0F);
    if (len < 126) {
        h[1] = (uint8_t)len; hl = 2;
    } else if (len <= 65535) {
        h[1] = 126;
        h[2] = (uint8_t)((len >> 8) & 0xFF);
        h[3] = (uint8_t)(len & 0xFF);
        hl = 4;
    } else {
        h[1] = 127;
