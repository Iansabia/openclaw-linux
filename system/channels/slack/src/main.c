/*
 * kelp-linux :: kelp-channel-slack
 * main.c - Slack channel plugin
 *
 * Connects to Slack via Socket Mode (WebSocket) for receiving events and
 * uses the Slack Web API for sending messages.  Forwards user messages to
 * kelp-gateway over a Unix domain socket (JSON-RPC), and posts the
 * assistant response back to the originating Slack channel.
 *
 * Usage: kelp-channel-slack [options]
 * Options:
 *   -c, --config <path>      Config file
 *   -t, --app-token <token>  App-level token (xapp-..., or $SLACK_APP_TOKEN)
 *   -b, --bot-token <token>  Bot token (xoxb-..., or $SLACK_BOT_TOKEN)
 *   -s, --socket <path>      Gateway Unix socket path
 *   -v, --verbose            Increase verbosity
 *   -h, --help               Help
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/kelp.h>
#include <kelp/config.h>
#include <kelp/http.h>

#include <cjson/cJSON.h>

#include <errno.h>
#include <getopt.h>
#include <netdb.h>
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
#include <openssl/ssl.h>

/* ---- Version ------------------------------------------------------------ */

#define SLACK_CHANNEL_VERSION "0.1.0"

/* ---- Slack API ---------------------------------------------------------- */

#define SLACK_API_BASE      "https://slack.com/api"
#define SLACK_WS_PORT       443
#define RPC_BUF_SIZE        65536

/* WebSocket frame opcodes */
#define WS_OP_TEXT      0x1
#define WS_OP_CLOSE     0x8
#define WS_OP_PING      0x9
#define WS_OP_PONG      0xA

#define WS_MAX_PAYLOAD  (1 * 1024 * 1024)

/* ---- Global state ------------------------------------------------------- */

static kelp_config_t        g_cfg;
static const char           *g_app_token    = NULL;
static const char           *g_bot_token    = NULL;
static const char           *g_socket_path  = NULL;
static int                   g_verbose      = 0;
static volatile sig_atomic_t g_shutdown     = 0;
static char                  g_bot_user_id[64] = {0};

/* TLS + WebSocket state */
static SSL_CTX              *g_ssl_ctx      = NULL;
static SSL                  *g_ssl          = NULL;
static int                   g_ws_fd        = -1;

/* ---- Signal handling ---------------------------------------------------- */

static void on_signal(int signo)
{
    (void)signo;
    g_shutdown = 1;
}

/* ---- TLS helpers -------------------------------------------------------- */

static int tls_init(void)
{
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) {
        KELP_ERROR("SSL_CTX_new failed");
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
    if (g_ws_fd >= 0) {
        close(g_ws_fd);
        g_ws_fd = -1;
    }
}

/* ---- TCP + TLS ---------------------------------------------------------- */

static int tls_connect(const char *host, int port)
{
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int err = getaddrinfo(host, port_str, &hints, &res);
    if (err != 0) {
        KELP_ERROR("getaddrinfo(%s): %s", host, gai_strerror(err));
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

    if (fd < 0) {
        KELP_ERROR("tcp_connect(%s:%d) failed", host, port);
        return -1;
    }

    g_ssl = SSL_new(g_ssl_ctx);
    if (!g_ssl) {
        close(fd);
        return -1;
    }

    SSL_set_fd(g_ssl, fd);
    SSL_set_tlsext_host_name(g_ssl, host);

    if (SSL_connect(g_ssl) <= 0) {
        KELP_ERROR("SSL_connect failed");
        SSL_free(g_ssl);
        g_ssl = NULL;
        close(fd);
        return -1;
    }

    g_ws_fd = fd;
    return 0;
}

/* ---- WebSocket framing (same as Discord plugin) ------------------------- */

static int ws_send_frame(uint8_t opcode, const void *data, size_t len)
{
    if (!g_ssl)
        return -1;

    uint8_t header[14];
    size_t hlen = 0;

    header[0] = 0x80 | (opcode & 0x0F);
    hlen++;

    if (len < 126) {
        header[1] = 0x80 | (uint8_t)len;
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

    uint8_t mask[4];
    uint32_t r = (uint32_t)rand();
    memcpy(mask, &r, 4);
    memcpy(header + hlen, mask, 4);
    hlen += 4;

    if (SSL_write(g_ssl, header, (int)hlen) <= 0)
        return -1;

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

    uint8_t mask_key[4] = {0};
    if (masked) {
        if (SSL_read(g_ssl, mask_key, 4) != 4)
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
            payload[i] ^= mask_key[i % 4];
    }

    payload[payload_len] = '\0';
    return payload;
}

/* ---- WebSocket handshake ------------------------------------------------ */

static int ws_handshake(const char *host, const char *path)
{
    uint8_t nonce[16];
    for (int i = 0; i < 16; i++)
        nonce[i] = (uint8_t)rand();

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

    if (SSL_write(g_ssl, request, req_len) <= 0)
        return -1;

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
        KELP_ERROR("ws_handshake: no 101 response:\n%s", response);
        return -1;
    }

    return 0;
}

/* ---- Gateway Unix socket (JSON-RPC) ------------------------------------- */

static char *gateway_chat(const char *message, const char *channel_id, const char *user_id)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return NULL;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", g_socket_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return NULL;
    }

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

    kelp_str_t resp = kelp_str_new();
    char buf[RPC_BUF_SIZE];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n <= 0)
            break;
        buf[n] = '\0';
        kelp_str_append(&resp, buf, (size_t)n);
        if (resp.len > 0 && resp.data[resp.len - 1] == '\n')
            break;
    }
    close(fd);

    if (resp.len == 0) {
        kelp_str_free(&resp);
        return NULL;
    }
    kelp_str_trim(&resp);

    cJSON *rpc_resp = cJSON_Parse(resp.data);
    kelp_str_free(&resp);
    if (!rpc_resp)
        return NULL;

    const char *content = NULL;
    cJSON *result = kelp_json_get_object(rpc_resp, "result");
    if (result)
        content = kelp_json_get_string(result, "content");

    char *out = content ? strdup(content) : NULL;
    cJSON_Delete(rpc_resp);
    return out;
}

/* ---- Slack Web API ------------------------------------------------------ */

static cJSON *slack_api_call(const char *method, cJSON *body)
{
    char url[256];
    snprintf(url, sizeof(url), "%s/%s", SLACK_API_BASE, method);

    char *body_str = NULL;
    if (body)
        body_str = cJSON_PrintUnformatted(body);

    kelp_http_header_t *headers = NULL;

    char auth[512];
    snprintf(auth, sizeof(auth), "Bearer %s", g_bot_token);
    kelp_http_header_add(&headers, "Authorization", auth);
    if (body_str)
        kelp_http_header_add(&headers, "Content-Type",
                              "application/json; charset=utf-8");

    kelp_http_request_t req = {
        .method           = body_str ? "POST" : "GET",
        .url              = url,
        .headers          = headers,
        .body             = body_str,
        .body_len         = body_str ? strlen(body_str) : 0,
        .timeout_ms       = 15000,
        .follow_redirects = true,
        .ca_bundle        = NULL
    };

    kelp_http_response_t resp;
    memset(&resp, 0, sizeof(resp));
    int ret = kelp_http_request(&req, &resp);

    free(body_str);
    kelp_http_header_free(headers);

    if (ret != KELP_OK) {
        KELP_ERROR("slack_api_call(%s): HTTP request failed", method);
        kelp_http_response_free(&resp);
        return NULL;
    }

    cJSON *root = cJSON_ParseWithLength((const char *)resp.body, resp.body_len);
    kelp_http_response_free(&resp);

    if (!root)
        return NULL;

    bool ok = kelp_json_get_bool(root, "ok", false);
    if (!ok) {
        const char *err_str = kelp_json_get_string(root, "error");
        KELP_ERROR("slack_api_call(%s): %s", method, err_str ? err_str : "?");
        cJSON_Delete(root);
        return NULL;
    }

    return root;
}

static int slack_send_message(const char *channel, const char *text)
{
    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "channel", channel);
    cJSON_AddStringToObject(body, "text", text);

    cJSON *result = slack_api_call("chat.postMessage", body);
    cJSON_Delete(body);

    if (result) {
        cJSON_Delete(result);
        return 0;
    }
    return -1;
}

/* ---- Slack Socket Mode -------------------------------------------------- */

/**
 * Get a WebSocket URL from Slack's apps.connections.open endpoint.
 * This requires the app-level token (xapp-...).
 * Returns a malloc'd URL string, or NULL on error.
 */
static char *slack_get_ws_url(void)
{
    char url[256];
    snprintf(url, sizeof(url), "%s/apps.connections.open", SLACK_API_BASE);

    kelp_http_header_t *headers = NULL;
    char auth[512];
    snprintf(auth, sizeof(auth), "Bearer %s", g_app_token);
    kelp_http_header_add(&headers, "Authorization", auth);
    kelp_http_header_add(&headers, "Content-Type", "application/x-www-form-urlencoded");

    kelp_http_request_t req = {
        .method           = "POST",
        .url              = url,
        .headers          = headers,
        .body             = "",
        .body_len         = 0,
        .timeout_ms       = 10000,
        .follow_redirects = true,
        .ca_bundle        = NULL
    };

    kelp_http_response_t resp;
    memset(&resp, 0, sizeof(resp));
    int ret = kelp_http_request(&req, &resp);
    kelp_http_header_free(headers);

    if (ret != KELP_OK) {
        KELP_ERROR("apps.connections.open failed");
        kelp_http_response_free(&resp);
        return NULL;
    }

    cJSON *root = cJSON_ParseWithLength((const char *)resp.body, resp.body_len);
    kelp_http_response_free(&resp);
    if (!root)
        return NULL;

    bool ok = kelp_json_get_bool(root, "ok", false);
    if (!ok) {
        const char *err_str = kelp_json_get_string(root, "error");
        KELP_ERROR("apps.connections.open: %s", err_str ? err_str : "?");
        cJSON_Delete(root);
        return NULL;
    }

    const char *ws_url = kelp_json_get_string(root, "url");
    char *result_url = ws_url ? strdup(ws_url) : NULL;
    cJSON_Delete(root);
    return result_url;
}

/**
 * Parse a wss:// URL into host, port, and path components.
 */
static int parse_wss_url(const char *url, char *host, size_t host_sz,
                         int *port, char *path, size_t path_sz)
{
    if (strncmp(url, "wss://", 6) != 0)
        return -1;

    const char *hp = url + 6;
    const char *slash = strchr(hp, '/');
    const char *colon = strchr(hp, ':');

    if (slash) {
        snprintf(path, path_sz, "%s", slash);
    } else {
        snprintf(path, path_sz, "/");
    }

    size_t host_len;
    if (colon && (!slash || colon < slash)) {
        host_len = (size_t)(colon - hp);
        *port = atoi(colon + 1);
    } else {
        host_len = slash ? (size_t)(slash - hp) : strlen(hp);
        *port = 443;
    }

    if (host_len >= host_sz)
        host_len = host_sz - 1;
    memcpy(host, hp, host_len);
    host[host_len] = '\0';

    return 0;
}

/* ---- Socket Mode message handling --------------------------------------- */

static void handle_slack_event(cJSON *envelope)
{
    const char *type = kelp_json_get_string(envelope, "type");
    const char *envelope_id = kelp_json_get_string(envelope, "envelope_id");

    /* Always acknowledge the envelope */
    if (envelope_id) {
        cJSON *ack = cJSON_CreateObject();
        cJSON_AddStringToObject(ack, "envelope_id", envelope_id);
        char *ack_str = cJSON_PrintUnformatted(ack);
        cJSON_Delete(ack);
        if (ack_str) {
            ws_send_text(ack_str);
            free(ack_str);
        }
    }

    if (!type)
        return;

    if (strcmp(type, "hello") == 0) {
        KELP_INFO("Socket Mode: connected (hello)");
        return;
    }

    if (strcmp(type, "disconnect") == 0) {
        const char *reason = kelp_json_get_string(envelope, "reason");
        KELP_INFO("Socket Mode: disconnect requested (reason=%s)",
                   reason ? reason : "?");
        g_shutdown = 1;
        return;
    }

    if (strcmp(type, "events_api") != 0)
        return;

    cJSON *payload = kelp_json_get_object(envelope, "payload");
    if (!payload)
        return;

    cJSON *event = kelp_json_get_object(payload, "event");
    if (!event)
        return;

    const char *event_type = kelp_json_get_string(event, "type");
    if (!event_type || strcmp(event_type, "message") != 0)
        return;

    /* Ignore subtypes (edits, joins, etc.) */
    const char *subtype = kelp_json_get_string(event, "subtype");
    if (subtype)
        return;

    const char *text    = kelp_json_get_string(event, "text");
    const char *channel = kelp_json_get_string(event, "channel");
    const char *user    = kelp_json_get_string(event, "user");

    if (!text || !channel || !user)
        return;

    /* Ignore our own messages */
    if (g_bot_user_id[0] != '\0' && strcmp(user, g_bot_user_id) == 0)
        return;

    /*
     * Check if the message is addressed to us:
     *   1. Direct mention: <@BOT_USER_ID>
     *   2. DM (channel starts with "D")
     */
    bool is_dm = (channel[0] == 'D');
    char mention_str[80];
    snprintf(mention_str, sizeof(mention_str), "<@%s>", g_bot_user_id);
    bool is_mentioned = (strstr(text, mention_str) != NULL);

    if (!is_dm && !is_mentioned)
        return;

    /* Strip the mention from the message */
    const char *msg = text;
    if (is_mentioned) {
        char *cleaned = kelp_str_replace(text, mention_str, "");
        if (cleaned) {
            /* Trim leading spaces */
            const char *p = cleaned;
            while (*p == ' ')
                p++;

            KELP_INFO("message from %s in %s: %.80s%s",
                       user, channel, p, strlen(p) > 80 ? "..." : "");

            char *response = gateway_chat(p, channel, user);
            free(cleaned);

            if (response && *response) {
                slack_send_message(channel, response);
            } else {
                slack_send_message(channel,
                    "I'm having trouble connecting to the gateway. "
                    "Please try again later.");
            }
            free(response);
            return;
        }
    }

    KELP_INFO("message from %s in %s: %.80s%s",
               user, channel, msg, strlen(msg) > 80 ? "..." : "");

    char *response = gateway_chat(msg, channel, user);

    if (response && *response) {
        slack_send_message(channel, response);
    } else {
        slack_send_message(channel,
            "I'm having trouble connecting to the gateway. "
            "Please try again later.");
    }
    free(response);
}

/* ---- Socket Mode receive loop ------------------------------------------- */

static int socket_mode_loop(void)
{
    while (!g_shutdown) {
        uint8_t opcode;
        char *frame = ws_recv_frame(&opcode);
        if (!frame) {
            if (g_shutdown)
                break;
            KELP_WARN("ws_recv_frame returned NULL, connection lost");
            return -1;
        }

        if (opcode == WS_OP_CLOSE) {
            KELP_INFO("received WebSocket CLOSE");
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
            KELP_DEBUG("<< %s", frame);

        cJSON *msg = cJSON_Parse(frame);
        free(frame);
        if (!msg)
            continue;

        handle_slack_event(msg);
        cJSON_Delete(msg);
    }

    return 0;
}

/* ---- Main --------------------------------------------------------------- */

static void print_usage(void)
{
    fprintf(stderr,
        "kelp-channel-slack %s\n"
        "Usage: kelp-channel-slack [options]\n"
        "\n"
        "Options:\n"
        "  -c, --config <path>      Config file\n"
        "  -t, --app-token <token>  App-level token (xapp-..., or $SLACK_APP_TOKEN)\n"
        "  -b, --bot-token <token>  Bot token (xoxb-..., or $SLACK_BOT_TOKEN)\n"
        "  -s, --socket <path>      Gateway Unix socket path\n"
        "  -v, --verbose            Increase verbosity\n"
        "  -h, --help               Help\n",
        SLACK_CHANNEL_VERSION);
}

int main(int argc, char *argv[])
{
    static struct option long_opts[] = {
        {"config",    required_argument, 0, 'c'},
        {"app-token", required_argument, 0, 't'},
        {"bot-token", required_argument, 0, 'b'},
        {"socket",    required_argument, 0, 's'},
        {"verbose",   no_argument,       0, 'v'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    const char *config_path = NULL;

    int opt;
    while ((opt = getopt_long(argc, argv, "c:t:b:s:vh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'c': config_path   = optarg; break;
        case 't': g_app_token   = optarg; break;
        case 'b': g_bot_token   = optarg; break;
        case 's': g_socket_path = optarg; break;
        case 'v': g_verbose++;            break;
        case 'h': print_usage(); return 0;
        default:  print_usage(); return 1;
        }
    }

    /* Logging */
    int log_level = KELP_LOG_INFO;
    if (g_verbose >= 2) log_level = KELP_LOG_TRACE;
    else if (g_verbose >= 1) log_level = KELP_LOG_DEBUG;
    kelp_log_init("slack", log_level);

    /* Load config */
    if (config_path) {
        if (kelp_config_load(config_path, &g_cfg) < 0) {
            KELP_ERROR("failed to load config: %s", config_path);
            return 1;
        }
    } else {
        kelp_config_load_default(&g_cfg);
    }
    kelp_config_merge_env(&g_cfg);

    /* Resolve tokens */
    if (!g_app_token)
        g_app_token = getenv("SLACK_APP_TOKEN");
    if (!g_bot_token)
        g_bot_token = getenv("SLACK_BOT_TOKEN");

    if (!g_app_token || *g_app_token == '\0') {
        fprintf(stderr,
            "error: Slack app-level token required.\n"
            "Set SLACK_APP_TOKEN or use --app-token <token>\n");
        kelp_config_free(&g_cfg);
        return 1;
    }
    if (!g_bot_token || *g_bot_token == '\0') {
        fprintf(stderr,
            "error: Slack bot token required.\n"
            "Set SLACK_BOT_TOKEN or use --bot-token <token>\n");
        kelp_config_free(&g_cfg);
        return 1;
    }

    /* Resolve gateway socket path */
    if (!g_socket_path)
        g_socket_path = g_cfg.gateway.socket_path;
    if (!g_socket_path)
        g_socket_path = "/run/kelp/gateway.sock";

    /* Signal handling */
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    kelp_http_init();

    KELP_INFO("kelp-channel-slack %s starting", SLACK_CHANNEL_VERSION);
    KELP_INFO("gateway socket: %s", g_socket_path);

    /* Verify bot token and get our user ID */
    cJSON *auth = slack_api_call("auth.test", NULL);
    if (auth) {
        const char *uid = kelp_json_get_string(auth, "user_id");
        const char *uname = kelp_json_get_string(auth, "user");
        if (uid)
            snprintf(g_bot_user_id, sizeof(g_bot_user_id), "%s", uid);
        KELP_INFO("authenticated as @%s (id=%s)",
                   uname ? uname : "?", g_bot_user_id);
        cJSON_Delete(auth);
    } else {
        KELP_ERROR("auth.test failed - check your bot token");
        kelp_http_cleanup();
        kelp_config_free(&g_cfg);
        return 1;
    }

    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    /* Reconnect loop */
    int backoff = 1;
    while (!g_shutdown) {
        /* Get a fresh WebSocket URL */
        char *ws_url = slack_get_ws_url();
        if (!ws_url) {
            KELP_ERROR("failed to get Socket Mode URL, retrying in %ds", backoff);
            sleep(backoff);
            if (backoff < 60)
                backoff *= 2;
            continue;
        }

        KELP_INFO("Socket Mode URL: %s", ws_url);

        /* Parse the URL */
        char host[256];
        int port;
        char path[1024];
        if (parse_wss_url(ws_url, host, sizeof(host),
                          &port, path, sizeof(path)) < 0) {
            KELP_ERROR("invalid WebSocket URL");
            free(ws_url);
            break;
        }
        free(ws_url);

        /* Connect */
        if (tls_init() < 0)
            break;

        if (tls_connect(host, port) < 0) {
            tls_cleanup();
            KELP_ERROR("TLS connection failed, retrying in %ds", backoff);
            sleep(backoff);
            if (backoff < 60)
                backoff *= 2;
            continue;
        }

        if (ws_handshake(host, path) < 0) {
            tls_cleanup();
            KELP_ERROR("WS handshake failed, retrying in %ds", backoff);
            sleep(backoff);
            if (backoff < 60)
                backoff *= 2;
            continue;
        }

        backoff = 1;
        int ret = socket_mode_loop();
        tls_cleanup();

        if (ret == 0 || g_shutdown)
            break;

        KELP_INFO("reconnecting in %ds...", backoff);
        sleep(backoff);
        if (backoff < 60)
            backoff *= 2;
    }

    /* Cleanup */
    tls_cleanup();
    kelp_http_cleanup();
    kelp_config_free(&g_cfg);

    KELP_INFO("kelp-channel-slack exited cleanly");
    return 0;
}
