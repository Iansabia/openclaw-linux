/*
 * clawd-linux :: clawd-channel-discord
 * main.c - Discord channel plugin
 *
 * Connects to the Discord Gateway (WebSocket API v10), listens for
 * MESSAGE_CREATE events, forwards user messages to clawd-gateway over
 * a Unix domain socket (JSON-RPC), and posts the assistant response
 * back to the originating Discord channel via the REST API.
 *
 * Usage: clawd-channel-discord [options]
 * Options:
 *   -c, --config <path>   Config file
 *   -t, --token <token>   Bot token (overrides $DISCORD_BOT_TOKEN)
 *   -s, --socket <path>   Gateway Unix socket path
 *   -v, --verbose         Increase verbosity
 *   -h, --help            Help
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/clawd.h>
#include <clawd/config.h>
#include <clawd/http.h>

#include <cjson/cJSON.h>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

/* ---- Version ------------------------------------------------------------ */

#define DISCORD_CHANNEL_VERSION "0.1.0"

/* ---- Discord API constants ---------------------------------------------- */

#define DISCORD_API_BASE        "https://discord.com/api/v10"
#define DISCORD_GATEWAY_URL     "wss://gateway.discord.gg/?v=10&encoding=json"
#define DISCORD_WS_HOST         "gateway.discord.gg"
#define DISCORD_WS_PORT         443
#define DISCORD_WS_PATH         "/?v=10&encoding=json"

/* Gateway opcodes */
#define GW_OP_DISPATCH          0
#define GW_OP_HEARTBEAT         1
#define GW_OP_IDENTIFY          2
#define GW_OP_PRESENCE          3
#define GW_OP_VOICE_STATE       4
#define GW_OP_RESUME            6
#define GW_OP_RECONNECT         7
#define GW_OP_REQUEST_MEMBERS   8
#define GW_OP_INVALID_SESSION   9
#define GW_OP_HELLO             10
#define GW_OP_HEARTBEAT_ACK     11

/* Gateway intents (bitfield) */
#define INTENT_GUILDS                   (1 << 0)
#define INTENT_GUILD_MESSAGES           (1 << 9)
#define INTENT_GUILD_MESSAGE_CONTENT    (1 << 15)
#define INTENT_DIRECT_MESSAGES          (1 << 12)

/* WebSocket frame opcodes */
#define WS_OP_TEXT      0x1
#define WS_OP_CLOSE     0x8
#define WS_OP_PING      0x9
#define WS_OP_PONG      0xA

/* Limits */
#define WS_MAX_PAYLOAD  (1 * 1024 * 1024)
#define RPC_BUF_SIZE    65536
#define MAX_BOT_PREFIX  "!"

/* ---- Global state ------------------------------------------------------- */

static clawd_config_t        g_cfg;
static const char           *g_bot_token      = NULL;
static const char           *g_socket_path    = NULL;
static const char           *g_bot_prefix     = "!clawd";
static int                   g_verbose        = 0;
static volatile sig_atomic_t g_shutdown       = 0;
static char                  g_session_id[128] = {0};
static char                  g_bot_user_id[64] = {0};
static int                   g_last_seq       = -1;

/* TLS + WebSocket state */
static SSL_CTX              *g_ssl_ctx        = NULL;
static SSL                  *g_ssl            = NULL;
static int                   g_ws_fd          = -1;

/* Heartbeat thread */
static pthread_t             g_heartbeat_tid;
static int                   g_heartbeat_interval_ms = 0;
static volatile bool         g_heartbeat_ack  = true;
static volatile bool         g_heartbeat_running = false;

/* ---- Signal handling ---------------------------------------------------- */

static void on_signal(int signo)
{
    (void)signo;
    g_shutdown = 1;
}

/* ---- TLS helpers -------------------------------------------------------- */

static int tls_init(void)
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) {
        CLAWD_ERROR("SSL_CTX_new failed");
        return -1;
    }

    SSL_CTX_set_default_verify_paths(g_ssl_ctx);
    SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_PEER, NULL);

    return 0;
}

static void tls_cleanup(void)
{
    if (g_ssl) {
        SSL_shutdown(g_ssl);
        SSL_free(g_ssl);
        g_ssl = NULL;
    }
    if (g_ssl_ctx) {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
    }
}

/* ---- TCP + TLS connection ----------------------------------------------- */

static int tcp_connect(const char *host, int port)
{
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int err = getaddrinfo(host, port_str, &hints, &res);
    if (err != 0) {
        CLAWD_ERROR("getaddrinfo(%s): %s", host, gai_strerror(err));
        return -1;
    }

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0)
        CLAWD_ERROR("tcp_connect(%s:%d): all addresses failed", host, port);

    return fd;
}

static int tls_connect(const char *host, int port)
{
    int fd = tcp_connect(host, port);
    if (fd < 0)
        return -1;

    g_ssl = SSL_new(g_ssl_ctx);
    if (!g_ssl) {
        close(fd);
        return -1;
    }

    SSL_set_fd(g_ssl, fd);
    SSL_set_tlsext_host_name(g_ssl, host);

    if (SSL_connect(g_ssl) <= 0) {
        CLAWD_ERROR("SSL_connect failed");
        SSL_free(g_ssl);
        g_ssl = NULL;
        close(fd);
        return -1;
    }

    g_ws_fd = fd;
    return 0;
}

/* ---- WebSocket framing -------------------------------------------------- */

static int ws_send_frame(uint8_t opcode, const void *data, size_t len)
{
    if (!g_ssl)
        return -1;

    /*
     * Client frames are always masked.  We use a simple random mask.
     */
    uint8_t header[14];
    size_t hlen = 0;

    header[0] = 0x80 | (opcode & 0x0F);  /* FIN + opcode */
    hlen++;

    if (len < 126) {
        header[1] = 0x80 | (uint8_t)len;  /* MASK bit set */
        hlen++;
    } else if (len <= 0xFFFF) {
        header[1] = 0x80 | 126;
        header[2] = (uint8_t)(len >> 8);
        header[3] = (uint8_t)(len & 0xFF);
        hlen += 3;
    } else {
        header[1] = 0x80 | 127;
        for (int i = 0; i < 8; i++)
            header[2 + i] = (uint8_t)(len >> (56 - 8 * i));
        hlen += 9;
    }

    /* Masking key (4 bytes) */
    uint8_t mask[4];
    uint32_t r = (uint32_t)rand();
    memcpy(mask, &r, 4);
    memcpy(header + hlen, mask, 4);
    hlen += 4;

    /* Send header */
    if (SSL_write(g_ssl, header, (int)hlen) <= 0)
        return -1;

    /* Send masked payload */
    if (len > 0) {
        uint8_t *masked = malloc(len);
        if (!masked)
            return -1;
        const uint8_t *src = data;
        for (size_t i = 0; i < len; i++)
            masked[i] = src[i] ^ mask[i % 4];
        int written = SSL_write(g_ssl, masked, (int)len);
        free(masked);
        if (written <= 0)
            return -1;
    }

    return 0;
}

static int ws_send_text(const char *text)
{
    return ws_send_frame(WS_OP_TEXT, text, strlen(text));
}

/**
 * Read a single WebSocket frame from the TLS connection.
 * Returns the payload as a malloc'd NUL-terminated string, or NULL on error.
 * Sets *opcode to the frame opcode.
 */
static char *ws_recv_frame(uint8_t *opcode)
{
    if (!g_ssl)
        return NULL;

    uint8_t hdr[2];
    if (SSL_read(g_ssl, hdr, 2) != 2)
        return NULL;

    *opcode = hdr[0] & 0x0F;
    bool masked = (hdr[1] & 0x80) != 0;
    uint64_t payload_len = hdr[1] & 0x7F;

    if (payload_len == 126) {
        uint8_t ext[2];
        if (SSL_read(g_ssl, ext, 2) != 2)
            return NULL;
        payload_len = ((uint64_t)ext[0] << 8) | ext[1];
    } else if (payload_len == 127) {
        uint8_t ext[8];
        if (SSL_read(g_ssl, ext, 8) != 8)
            return NULL;
        payload_len = 0;
        for (int i = 0; i < 8; i++)
            payload_len = (payload_len << 8) | ext[i];
    }

    if (payload_len > WS_MAX_PAYLOAD)
        return NULL;

    uint8_t mask[4] = {0};
    if (masked) {
        if (SSL_read(g_ssl, mask, 4) != 4)
            return NULL;
    }

    char *payload = malloc((size_t)payload_len + 1);
    if (!payload)
        return NULL;

    size_t total_read = 0;
    while (total_read < payload_len) {
        int n = SSL_read(g_ssl, payload + total_read,
                         (int)(payload_len - total_read));
        if (n <= 0) {
            free(payload);
            return NULL;
        }
        total_read += (size_t)n;
    }

    if (masked) {
        for (size_t i = 0; i < payload_len; i++)
            payload[i] ^= mask[i % 4];
    }

    payload[payload_len] = '\0';
    return payload;
}

/* ---- WebSocket handshake ------------------------------------------------ */

static int ws_handshake(const char *host, const char *path)
{
    /* Generate a random 16-byte key, base64-encoded */
    uint8_t nonce[16];
    for (int i = 0; i < 16; i++)
        nonce[i] = (uint8_t)rand();

    /* Base64 encode via OpenSSL BIO */
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, nonce, sizeof(nonce));
    BIO_flush(b64);

    char *b64_data = NULL;
    long b64_len = BIO_get_mem_data(mem, &b64_data);

    char ws_key[64];
    snprintf(ws_key, sizeof(ws_key), "%.*s", (int)b64_len, b64_data);
    BIO_free_all(b64);

    /* Build HTTP upgrade request */
    char request[1024];
    int req_len = snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        path, host, ws_key);

    if (SSL_write(g_ssl, request, req_len) <= 0) {
        CLAWD_ERROR("ws_handshake: failed to send upgrade request");
        return -1;
    }

    /* Read the HTTP response (we just need 101 Switching Protocols) */
    char response[4096];
    int resp_len = 0;
    while (resp_len < (int)sizeof(response) - 1) {
        int n = SSL_read(g_ssl, response + resp_len, 1);
        if (n <= 0)
            return -1;
        resp_len++;
        if (resp_len >= 4 &&
            response[resp_len - 4] == '\r' &&
            response[resp_len - 3] == '\n' &&
            response[resp_len - 2] == '\r' &&
            response[resp_len - 1] == '\n')
            break;
    }
    response[resp_len] = '\0';

    if (strstr(response, "101") == NULL) {
        CLAWD_ERROR("ws_handshake: did not get 101 response:\n%s", response);
        return -1;
    }

    CLAWD_DEBUG("WebSocket handshake complete");
    return 0;
}

/* ---- Discord Gateway protocol ------------------------------------------- */

static int gw_send_json(cJSON *obj)
{
    char *text = cJSON_PrintUnformatted(obj);
    if (!text)
        return -1;

    if (g_verbose >= 2)
        CLAWD_DEBUG(">> %s", text);

    int ret = ws_send_text(text);
    free(text);
    return ret;
}

static int gw_send_heartbeat(void)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "op", GW_OP_HEARTBEAT);
    if (g_last_seq >= 0)
        cJSON_AddNumberToObject(obj, "d", g_last_seq);
    else
        cJSON_AddNullToObject(obj, "d");

    int ret = gw_send_json(obj);
    cJSON_Delete(obj);
    return ret;
}

static int gw_send_identify(void)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "op", GW_OP_IDENTIFY);

    cJSON *d = cJSON_AddObjectToObject(obj, "d");
    cJSON_AddStringToObject(d, "token", g_bot_token);

    int intents = INTENT_GUILDS
                | INTENT_GUILD_MESSAGES
                | INTENT_GUILD_MESSAGE_CONTENT
                | INTENT_DIRECT_MESSAGES;
    cJSON_AddNumberToObject(d, "intents", intents);

    cJSON *props = cJSON_AddObjectToObject(d, "properties");
    cJSON_AddStringToObject(props, "os", "linux");
    cJSON_AddStringToObject(props, "browser", "clawd");
    cJSON_AddStringToObject(props, "device", "clawd");

    int ret = gw_send_json(obj);
    cJSON_Delete(obj);

    CLAWD_INFO("sent IDENTIFY");
    return ret;
}

static int gw_send_resume(void)
{
    if (g_session_id[0] == '\0' || g_last_seq < 0)
        return gw_send_identify();

    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "op", GW_OP_RESUME);

    cJSON *d = cJSON_AddObjectToObject(obj, "d");
    cJSON_AddStringToObject(d, "token", g_bot_token);
    cJSON_AddStringToObject(d, "session_id", g_session_id);
    cJSON_AddNumberToObject(d, "seq", g_last_seq);

    int ret = gw_send_json(obj);
    cJSON_Delete(obj);

    CLAWD_INFO("sent RESUME (session=%s, seq=%d)", g_session_id, g_last_seq);
    return ret;
}

/* ---- Heartbeat thread --------------------------------------------------- */

static void *heartbeat_thread(void *arg)
{
    (void)arg;
    CLAWD_DEBUG("heartbeat thread started (interval=%d ms)",
                g_heartbeat_interval_ms);

    /* Initial jitter: wait a random fraction of the interval */
    int jitter_ms = rand() % g_heartbeat_interval_ms;
    struct timespec ts = {
        .tv_sec  = jitter_ms / 1000,
        .tv_nsec = (jitter_ms % 1000) * 1000000L
    };
    nanosleep(&ts, NULL);

    while (!g_shutdown && g_heartbeat_running) {
        if (!g_heartbeat_ack) {
            CLAWD_WARN("heartbeat ACK not received, connection may be zombied");
        }

        g_heartbeat_ack = false;
        gw_send_heartbeat();

        /* Sleep for heartbeat interval */
        ts.tv_sec  = g_heartbeat_interval_ms / 1000;
        ts.tv_nsec = (g_heartbeat_interval_ms % 1000) * 1000000L;
        nanosleep(&ts, NULL);
    }

    CLAWD_DEBUG("heartbeat thread exiting");
    return NULL;
}

static void heartbeat_start(int interval_ms)
{
    g_heartbeat_interval_ms = interval_ms;
    g_heartbeat_ack = true;
    g_heartbeat_running = true;
    pthread_create(&g_heartbeat_tid, NULL, heartbeat_thread, NULL);
}

static void heartbeat_stop(void)
{
    g_heartbeat_running = false;
    pthread_join(g_heartbeat_tid, NULL);
}

/* ---- Gateway Unix socket (JSON-RPC to clawd-gateway) -------------------- */

static int gateway_connect_unix(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        CLAWD_ERROR("socket(AF_UNIX): %s", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        CLAWD_ERROR("connect(%s): %s", path, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

/**
 * Send a chat message to clawd-gateway via JSON-RPC and return the response.
 * Caller must free the returned string.
 */
static char *gateway_chat(const char *message,
                           const char *channel_id,
                           const char *user_id)
{
    int fd = gateway_connect_unix(g_socket_path);
    if (fd < 0)
        return NULL;

    static int rpc_id = 1;

    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "message", message);
    if (channel_id)
        cJSON_AddStringToObject(params, "channel_id", channel_id);
    if (user_id)
        cJSON_AddStringToObject(params, "user_id", user_id);

    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "jsonrpc", "2.0");
    cJSON_AddNumberToObject(req, "id", rpc_id++);
    cJSON_AddStringToObject(req, "method", "chat.send");
    cJSON_AddItemToObject(req, "params", params);

    char *payload = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);
    if (!payload) {
        close(fd);
        return NULL;
    }

    /* Send with newline delimiter */
    size_t plen = strlen(payload);
    char *sendbuf = malloc(plen + 2);
    if (!sendbuf) {
        free(payload);
        close(fd);
        return NULL;
    }
    memcpy(sendbuf, payload, plen);
    sendbuf[plen]     = '\n';
    sendbuf[plen + 1] = '\0';
    free(payload);

    ssize_t total = (ssize_t)(plen + 1);
    ssize_t sent = 0;
    while (sent < total) {
        ssize_t n = write(fd, sendbuf + sent, (size_t)(total - sent));
        if (n <= 0) {
            free(sendbuf);
            close(fd);
            return NULL;
        }
        sent += n;
    }
    free(sendbuf);

    /* Read response */
    clawd_str_t resp = clawd_str_new();
    char buf[RPC_BUF_SIZE];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n <= 0)
            break;
        buf[n] = '\0';
        clawd_str_append(&resp, buf, (size_t)n);
        if (resp.len > 0 && resp.data[resp.len - 1] == '\n')
            break;
    }
    close(fd);

    if (resp.len == 0) {
        clawd_str_free(&resp);
        return NULL;
    }
    clawd_str_trim(&resp);

    /* Parse JSON-RPC response and extract the content */
    cJSON *rpc_resp = cJSON_Parse(resp.data);
    clawd_str_free(&resp);
    if (!rpc_resp)
        return NULL;

    const char *content = NULL;
    cJSON *result = clawd_json_get_object(rpc_resp, "result");
    if (result) {
        content = clawd_json_get_string(result, "content");
    } else {
        /* Try extracting from error */
        cJSON *error = clawd_json_get_object(rpc_resp, "error");
        if (error)
            content = clawd_json_get_string(error, "message");
    }

    char *out = content ? strdup(content) : NULL;
    cJSON_Delete(rpc_resp);
    return out;
}

/* ---- Discord REST API --------------------------------------------------- */

/**
 * Send a message to a Discord channel via REST API.
 */
static int discord_send_message(const char *channel_id, const char *content)
{
    char url[256];
    snprintf(url, sizeof(url), "%s/channels/%s/messages",
             DISCORD_API_BASE, channel_id);

    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "content", content);
    char *body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str)
        return -1;

    clawd_http_header_t *headers = NULL;

    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Bot %s", g_bot_token);
    clawd_http_header_add(&headers, "Authorization", auth_header);
    clawd_http_header_add(&headers, "Content-Type", "application/json");
    clawd_http_header_add(&headers, "User-Agent", "clawd-channel-discord/0.1.0");

    clawd_http_request_t req = {
        .method           = "POST",
        .url              = url,
        .headers          = headers,
        .body             = body_str,
        .body_len         = strlen(body_str),
        .timeout_ms       = 10000,
        .follow_redirects = true,
        .ca_bundle        = NULL
    };

    clawd_http_response_t resp;
    memset(&resp, 0, sizeof(resp));
    int ret = clawd_http_request(&req, &resp);

    if (ret != CLAWD_OK) {
        CLAWD_ERROR("discord REST: HTTP request failed");
    } else if (resp.status_code < 200 || resp.status_code >= 300) {
        CLAWD_ERROR("discord REST: HTTP %d: %.*s",
                    resp.status_code,
                    (int)(resp.body_len > 200 ? 200 : resp.body_len),
                    resp.body);
    } else {
        CLAWD_DEBUG("discord REST: message sent to channel %s", channel_id);
    }

    clawd_http_response_free(&resp);
    clawd_http_header_free(headers);
    free(body_str);
    return (ret == CLAWD_OK && resp.status_code >= 200 && resp.status_code < 300)
               ? 0 : -1;
}

/**
 * Send a typing indicator to a Discord channel.
 */
static int discord_send_typing(const char *channel_id)
{
    char url[256];
    snprintf(url, sizeof(url), "%s/channels/%s/typing",
             DISCORD_API_BASE, channel_id);

    clawd_http_header_t *headers = NULL;

    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Bot %s", g_bot_token);
    clawd_http_header_add(&headers, "Authorization", auth_header);
    clawd_http_header_add(&headers, "User-Agent", "clawd-channel-discord/0.1.0");

    clawd_http_request_t req = {
        .method           = "POST",
        .url              = url,
        .headers          = headers,
        .body             = NULL,
        .body_len         = 0,
        .timeout_ms       = 5000,
        .follow_redirects = true,
        .ca_bundle        = NULL
    };

    clawd_http_response_t resp;
    memset(&resp, 0, sizeof(resp));
    int ret = clawd_http_request(&req, &resp);

    clawd_http_response_free(&resp);
    clawd_http_header_free(headers);
    return ret;
}

/* ---- Discord message handling ------------------------------------------- */

/**
 * Handle a MESSAGE_CREATE event from the Discord gateway.
 */
static void handle_message_create(cJSON *data)
{
    const char *content    = clawd_json_get_string(data, "content");
    const char *channel_id = clawd_json_get_string(data, "channel_id");

    cJSON *author = clawd_json_get_object(data, "author");
    if (!author || !content || !channel_id)
        return;

    const char *author_id  = clawd_json_get_string(author, "id");
    const char *username   = clawd_json_get_string(author, "username");
    bool is_bot = clawd_json_get_bool(author, "bot", false);

    /* Ignore messages from bots (including ourselves) */
    if (is_bot)
        return;

    /* Ignore messages from ourselves (extra safety) */
    if (author_id && g_bot_user_id[0] != '\0' &&
        strcmp(author_id, g_bot_user_id) == 0)
        return;

    /*
     * Check if the message is addressed to us:
     *   1. Starts with the bot prefix (e.g. "!clawd")
     *   2. Mentions the bot user
     *   3. Is a DM (no guild_id)
     */
    const char *guild_id = clawd_json_get_string(data, "guild_id");
    bool is_dm = (guild_id == NULL);

    /* Check for bot mention in the mentions array */
    bool is_mentioned = false;
    cJSON *mentions = clawd_json_get_array(data, "mentions");
    if (mentions) {
        cJSON *m = NULL;
        cJSON_ArrayForEach(m, mentions) {
            const char *mid = clawd_json_get_string(m, "id");
            if (mid && g_bot_user_id[0] != '\0' &&
                strcmp(mid, g_bot_user_id) == 0) {
                is_mentioned = true;
                break;
            }
        }
    }

    bool has_prefix = clawd_str_starts_with(content, g_bot_prefix);

    if (!is_dm && !is_mentioned && !has_prefix)
        return;

    /* Extract the actual message content */
    const char *msg = content;
    if (has_prefix) {
        msg = content + strlen(g_bot_prefix);
        while (*msg == ' ')
            msg++;
    } else if (is_mentioned) {
        /* Strip the <@BOT_ID> mention from the beginning if present */
        char mention_str[80];
        snprintf(mention_str, sizeof(mention_str), "<@%s>", g_bot_user_id);
        if (clawd_str_starts_with(msg, mention_str)) {
            msg += strlen(mention_str);
            while (*msg == ' ')
                msg++;
        }
    }

    if (*msg == '\0')
        return;

    CLAWD_INFO("message from %s in channel %s: %.80s%s",
               username ? username : "unknown",
               channel_id, msg, strlen(msg) > 80 ? "..." : "");

    /* Show typing indicator while we process */
    discord_send_typing(channel_id);

    /* Forward to clawd-gateway */
    char *response = gateway_chat(msg, channel_id, author_id);

    if (response && *response) {
        /* Discord messages have a 2000 char limit; split if needed */
        size_t resp_len = strlen(response);
        size_t offset = 0;

        while (offset < resp_len) {
            size_t chunk_len = resp_len - offset;
            if (chunk_len > 1990)
                chunk_len = 1990;

            char saved = response[offset + chunk_len];
            response[offset + chunk_len] = '\0';
            discord_send_message(channel_id, response + offset);
            response[offset + chunk_len] = saved;

            offset += chunk_len;
        }
    } else {
        discord_send_message(channel_id,
            "I'm having trouble connecting to the gateway. "
            "Please try again later.");
    }

    free(response);
}

/* ---- Gateway event dispatch --------------------------------------------- */

static void handle_gateway_event(const char *event_name, cJSON *data)
{
    if (strcmp(event_name, "READY") == 0) {
        const char *sid = clawd_json_get_string(data, "session_id");
        if (sid) {
            snprintf(g_session_id, sizeof(g_session_id), "%s", sid);
            CLAWD_INFO("READY: session_id=%s", g_session_id);
        }

        /* Extract our own user ID */
        cJSON *user = clawd_json_get_object(data, "user");
        if (user) {
            const char *uid = clawd_json_get_string(user, "id");
            const char *uname = clawd_json_get_string(user, "username");
            if (uid)
                snprintf(g_bot_user_id, sizeof(g_bot_user_id), "%s", uid);
            CLAWD_INFO("logged in as %s (id=%s)",
                       uname ? uname : "?", g_bot_user_id);
        }
    } else if (strcmp(event_name, "RESUMED") == 0) {
        CLAWD_INFO("session resumed");
    } else if (strcmp(event_name, "MESSAGE_CREATE") == 0) {
        handle_message_create(data);
    } else if (strcmp(event_name, "GUILD_CREATE") == 0) {
        const char *name = clawd_json_get_string(data, "name");
        CLAWD_INFO("joined guild: %s", name ? name : "(unknown)");
    } else {
        CLAWD_DEBUG("unhandled event: %s", event_name);
    }
}

/* ---- Main gateway receive loop ------------------------------------------ */

static int gateway_loop(void)
{
    while (!g_shutdown) {
        uint8_t opcode;
        char *frame = ws_recv_frame(&opcode);
        if (!frame) {
            if (g_shutdown)
                break;
            CLAWD_WARN("ws_recv_frame returned NULL, connection lost");
            return -1;  /* Signal reconnect */
        }

        if (opcode == WS_OP_CLOSE) {
            CLAWD_INFO("received WebSocket CLOSE frame");
            free(frame);
            return -1;
        }

        if (opcode == WS_OP_PING) {
            ws_send_frame(WS_OP_PONG, frame, strlen(frame));
            free(frame);
            continue;
        }

        if (opcode != WS_OP_TEXT) {
            free(frame);
            continue;
        }

        if (g_verbose >= 2)
            CLAWD_DEBUG("<< %s", frame);

        cJSON *msg = cJSON_Parse(frame);
        free(frame);
        if (!msg)
            continue;

        int op = clawd_json_get_int(msg, "op", -1);

        /* Track sequence number */
        cJSON *s_node = cJSON_GetObjectItem(msg, "s");
        if (s_node && cJSON_IsNumber(s_node))
            g_last_seq = (int)s_node->valuedouble;

        switch (op) {
        case GW_OP_DISPATCH: {
            const char *t = clawd_json_get_string(msg, "t");
            cJSON *d = cJSON_GetObjectItem(msg, "d");
            if (t && d)
                handle_gateway_event(t, d);
            break;
        }
        case GW_OP_HELLO: {
            cJSON *d = cJSON_GetObjectItem(msg, "d");
            int interval = clawd_json_get_int(d, "heartbeat_interval", 45000);
            CLAWD_INFO("HELLO: heartbeat_interval=%d ms", interval);
            heartbeat_start(interval);

            /* Send IDENTIFY or RESUME */
            if (g_session_id[0] != '\0')
                gw_send_resume();
            else
                gw_send_identify();
            break;
        }
        case GW_OP_HEARTBEAT:
            gw_send_heartbeat();
            break;

        case GW_OP_HEARTBEAT_ACK:
            g_heartbeat_ack = true;
            break;

        case GW_OP_RECONNECT:
            CLAWD_INFO("server requested RECONNECT");
            cJSON_Delete(msg);
            return -1;

        case GW_OP_INVALID_SESSION: {
            cJSON *d_node = cJSON_GetObjectItem(msg, "d");
            bool resumable = (d_node && cJSON_IsTrue(d_node));
            CLAWD_WARN("INVALID_SESSION (resumable=%s)",
                       resumable ? "true" : "false");
            if (!resumable) {
                g_session_id[0] = '\0';
                g_last_seq = -1;
            }
            /* Wait a bit then reconnect */
            struct timespec wait = { .tv_sec = 1 + rand() % 5, .tv_nsec = 0 };
            nanosleep(&wait, NULL);
            cJSON_Delete(msg);
            return -1;
        }
        default:
            CLAWD_DEBUG("unknown opcode: %d", op);
            break;
        }

        cJSON_Delete(msg);
    }

    return 0;
}

/* ---- Connection lifecycle ----------------------------------------------- */

static int connect_to_discord(void)
{
    CLAWD_INFO("connecting to Discord Gateway...");

    if (tls_connect(DISCORD_WS_HOST, DISCORD_WS_PORT) < 0) {
        CLAWD_ERROR("TLS connection to Discord failed");
        return -1;
    }

    if (ws_handshake(DISCORD_WS_HOST, DISCORD_WS_PATH) < 0) {
        CLAWD_ERROR("WebSocket handshake failed");
        tls_cleanup();
        return -1;
    }

    CLAWD_INFO("connected to Discord Gateway");
    return 0;
}

static void disconnect_from_discord(void)
{
    if (g_heartbeat_running)
        heartbeat_stop();

    /* Send a close frame */
    if (g_ssl)
        ws_send_frame(WS_OP_CLOSE, NULL, 0);

    tls_cleanup();

    if (g_ws_fd >= 0) {
        close(g_ws_fd);
        g_ws_fd = -1;
    }

    CLAWD_INFO("disconnected from Discord");
}

/* ---- Main --------------------------------------------------------------- */

static void print_usage(void)
{
    fprintf(stderr,
        "clawd-channel-discord %s\n"
        "Usage: clawd-channel-discord [options]\n"
        "\n"
        "Options:\n"
        "  -c, --config <path>   Config file\n"
        "  -t, --token <token>   Bot token (or set $DISCORD_BOT_TOKEN)\n"
        "  -s, --socket <path>   Gateway Unix socket path\n"
        "  -P, --prefix <str>    Bot command prefix (default: !clawd)\n"
        "  -v, --verbose         Increase verbosity\n"
        "  -h, --help            Help\n",
        DISCORD_CHANNEL_VERSION);
}

int main(int argc, char *argv[])
{
    static struct option long_opts[] = {
        {"config",  required_argument, 0, 'c'},
        {"token",   required_argument, 0, 't'},
        {"socket",  required_argument, 0, 's'},
        {"prefix",  required_argument, 0, 'P'},
        {"verbose", no_argument,       0, 'v'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    const char *config_path = NULL;

    int opt;
    while ((opt = getopt_long(argc, argv, "c:t:s:P:vh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'c': config_path  = optarg; break;
        case 't': g_bot_token  = optarg; break;
        case 's': g_socket_path = optarg; break;
        case 'P': g_bot_prefix = optarg; break;
        case 'v': g_verbose++;           break;
        case 'h': print_usage(); return 0;
        default:  print_usage(); return 1;
        }
    }

    /* Logging */
    int log_level = CLAWD_LOG_INFO;
    if (g_verbose >= 2) log_level = CLAWD_LOG_TRACE;
    else if (g_verbose >= 1) log_level = CLAWD_LOG_DEBUG;
    clawd_log_init("discord", log_level);

    /* Load config */
    if (config_path) {
        if (clawd_config_load(config_path, &g_cfg) < 0) {
            CLAWD_ERROR("failed to load config: %s", config_path);
            return 1;
        }
    } else {
        clawd_config_load_default(&g_cfg);
    }
    clawd_config_merge_env(&g_cfg);

    /* Resolve bot token */
    if (!g_bot_token)
        g_bot_token = getenv("DISCORD_BOT_TOKEN");
    if (!g_bot_token || *g_bot_token == '\0') {
        fprintf(stderr,
            "error: Discord bot token required.\n"
            "Set DISCORD_BOT_TOKEN or use --token <token>\n");
        clawd_config_free(&g_cfg);
        return 1;
    }

    /* Resolve gateway socket path */
    if (!g_socket_path) {
        g_socket_path = g_cfg.gateway.socket_path;
    }
    if (!g_socket_path) {
        g_socket_path = "/run/clawd/gateway.sock";
    }

    /* Signal handling */
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    /* Init HTTP client (for REST API calls) */
    clawd_http_init();

    /* Init TLS */
    if (tls_init() < 0) {
        clawd_http_cleanup();
        clawd_config_free(&g_cfg);
        return 1;
    }

    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    CLAWD_INFO("clawd-channel-discord %s starting", DISCORD_CHANNEL_VERSION);
    CLAWD_INFO("gateway socket: %s", g_socket_path);
    CLAWD_INFO("bot prefix: \"%s\"", g_bot_prefix);

    /* Reconnect loop */
    int backoff = 1;
    while (!g_shutdown) {
        if (connect_to_discord() == 0) {
            backoff = 1;
            int ret = gateway_loop();
            disconnect_from_discord();

            if (ret == 0 || g_shutdown)
                break;

            CLAWD_INFO("will reconnect in %d seconds...", backoff);
        } else {
            CLAWD_ERROR("connection failed, retrying in %d seconds...", backoff);
        }

        /* Exponential backoff with cap */
        struct timespec wait = { .tv_sec = backoff, .tv_nsec = 0 };
        nanosleep(&wait, NULL);
        if (backoff < 60)
            backoff *= 2;

        /* Reinit TLS for reconnect */
        tls_cleanup();
        if (tls_init() < 0)
            break;
    }

    /* Cleanup */
    tls_cleanup();
    clawd_http_cleanup();
    clawd_config_free(&g_cfg);

    CLAWD_INFO("clawd-channel-discord exited cleanly");
    return 0;
}
