/*
 * kelp-linux :: kelp-channel-telegram
 * main.c - Telegram channel plugin
 *
 * Connects to the Telegram Bot API via HTTP long-polling (getUpdates),
 * forwards user messages to kelp-gateway over a Unix domain socket
 * (JSON-RPC), and posts the assistant response back via sendMessage.
 *
 * Usage: kelp-channel-telegram [options]
 * Options:
 *   -c, --config <path>   Config file
 *   -t, --token <token>   Bot token (overrides $TELEGRAM_BOT_TOKEN)
 *   -s, --socket <path>   Gateway Unix socket path
 *   -v, --verbose         Increase verbosity
 *   -h, --help            Help
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/kelp.h>
#include <kelp/config.h>
#include <kelp/http.h>

#include <cjson/cJSON.h>

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>

/* ---- Version ------------------------------------------------------------ */

#define TELEGRAM_CHANNEL_VERSION "0.1.0"

/* ---- Telegram API ------------------------------------------------------- */

#define TELEGRAM_API_BASE "https://api.telegram.org/bot"
#define POLL_TIMEOUT_SEC  30
#define RPC_BUF_SIZE      65536

/* ---- Global state ------------------------------------------------------- */

static kelp_config_t        g_cfg;
static const char           *g_bot_token    = NULL;
static const char           *g_socket_path  = NULL;
static int                   g_verbose      = 0;
static volatile sig_atomic_t g_shutdown     = 0;
static int64_t               g_update_offset = 0;
static char                  g_bot_username[128] = {0};

/* ---- Signal handling ---------------------------------------------------- */

static void on_signal(int signo)
{
    (void)signo;
    g_shutdown = 1;
}

/* ---- Telegram API helpers ----------------------------------------------- */

static char *tg_api_url(const char *method)
{
    size_t len = strlen(TELEGRAM_API_BASE) + strlen(g_bot_token) +
                 1 + strlen(method) + 1;
    char *url = malloc(len);
    if (url)
        snprintf(url, len, "%s%s/%s", TELEGRAM_API_BASE, g_bot_token, method);
    return url;
}

/**
 * Make a Telegram Bot API call with a JSON body.
 * Returns the parsed "result" field from the response, or NULL on error.
 * Caller must cJSON_Delete the returned object.
 */
static cJSON *tg_api_call(const char *method, cJSON *params)
{
    char *url = tg_api_url(method);
    if (!url)
        return NULL;

    char *body_str = NULL;
    if (params)
        body_str = cJSON_PrintUnformatted(params);

    kelp_http_header_t *headers = NULL;
    if (body_str)
        kelp_http_header_add(&headers, "Content-Type", "application/json");

    kelp_http_request_t req = {
        .method           = body_str ? "POST" : "GET",
        .url              = url,
        .headers          = headers,
        .body             = body_str,
        .body_len         = body_str ? strlen(body_str) : 0,
        .timeout_ms       = (POLL_TIMEOUT_SEC + 10) * 1000,
        .follow_redirects = true,
        .ca_bundle        = NULL
    };

    kelp_http_response_t resp;
    memset(&resp, 0, sizeof(resp));
    int ret = kelp_http_request(&req, &resp);

    free(url);
    free(body_str);
    kelp_http_header_free(headers);

    if (ret != KELP_OK) {
        KELP_ERROR("tg_api_call(%s): HTTP request failed", method);
        kelp_http_response_free(&resp);
        return NULL;
    }

    if (resp.status_code < 200 || resp.status_code >= 300) {
        KELP_ERROR("tg_api_call(%s): HTTP %d", method, resp.status_code);
        kelp_http_response_free(&resp);
        return NULL;
    }

    cJSON *root = cJSON_ParseWithLength((const char *)resp.body, resp.body_len);
    kelp_http_response_free(&resp);

    if (!root) {
        KELP_ERROR("tg_api_call(%s): invalid JSON response", method);
        return NULL;
    }

    bool ok = kelp_json_get_bool(root, "ok", false);
    if (!ok) {
        const char *desc = kelp_json_get_string(root, "description");
        KELP_ERROR("tg_api_call(%s): error: %s", method, desc ? desc : "?");
        cJSON_Delete(root);
        return NULL;
    }

    /* Detach the "result" node */
    cJSON *result = cJSON_DetachItemFromObject(root, "result");
    cJSON_Delete(root);
    return result;
}

/* ---- Gateway Unix socket (JSON-RPC) ------------------------------------- */

static char *gateway_chat(const char *message, const char *channel_id,
                          const char *user_id)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        KELP_ERROR("socket(AF_UNIX): %s", strerror(errno));
        return NULL;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", g_socket_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        KELP_ERROR("connect(%s): %s", g_socket_path, strerror(errno));
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

    /* Read response */
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
    else {
        cJSON *error = kelp_json_get_object(rpc_resp, "error");
        if (error)
            content = kelp_json_get_string(error, "message");
    }

    char *out = content ? strdup(content) : NULL;
    cJSON_Delete(rpc_resp);
    return out;
}

/* ---- Telegram message handling ------------------------------------------ */

static int tg_send_message(int64_t chat_id, const char *text)
{
    cJSON *params = cJSON_CreateObject();
    cJSON_AddNumberToObject(params, "chat_id", (double)chat_id);
    cJSON_AddStringToObject(params, "text", text);

    cJSON *result = tg_api_call("sendMessage", params);
    cJSON_Delete(params);

    if (result) {
        cJSON_Delete(result);
        return 0;
    }
    return -1;
}

static int tg_send_chat_action(int64_t chat_id, const char *action)
{
    cJSON *params = cJSON_CreateObject();
    cJSON_AddNumberToObject(params, "chat_id", (double)chat_id);
    cJSON_AddStringToObject(params, "action", action);

    cJSON *result = tg_api_call("sendChatAction", params);
    cJSON_Delete(params);

    if (result) {
        cJSON_Delete(result);
        return 0;
    }
    return -1;
}

static void handle_update(cJSON *update)
{
    /* Track offset for next getUpdates call */
    int64_t update_id = (int64_t)kelp_json_get_int(update, "update_id", 0);
    if (update_id >= g_update_offset)
        g_update_offset = update_id + 1;

    cJSON *message = kelp_json_get_object(update, "message");
    if (!message)
        return;

    const char *text = kelp_json_get_string(message, "text");
    if (!text || *text == '\0')
        return;

    cJSON *chat = kelp_json_get_object(message, "chat");
    if (!chat)
        return;

    int64_t chat_id = (int64_t)kelp_json_get_int(chat, "id", 0);
    if (chat_id == 0)
        return;

    const char *chat_type = kelp_json_get_string(chat, "type");

    cJSON *from = kelp_json_get_object(message, "from");
    const char *username = from ? kelp_json_get_string(from, "username") : NULL;
    const char *first_name = from ? kelp_json_get_string(from, "first_name") : NULL;
    bool is_bot = from ? kelp_json_get_bool(from, "is_bot", false) : false;

    /* Ignore messages from bots */
    if (is_bot)
        return;

    /*
     * In groups, only respond to:
     *   1. Messages starting with /kelp
     *   2. Messages that mention @bot_username
     *   3. Reply to our messages (not implemented yet)
     * In private chats, respond to everything.
     */
    bool is_private = (chat_type && strcmp(chat_type, "private") == 0);
    const char *msg = text;

    if (!is_private) {
        if (kelp_str_starts_with(text, "/kelp")) {
            msg = text + 6;  /* strlen("/kelp") */
            if (*msg == '@')  /* skip /kelp@botname */
                msg = strchr(msg, ' ') ? strchr(msg, ' ') : msg + strlen(msg);
            while (*msg == ' ')
                msg++;
        } else if (g_bot_username[0] != '\0') {
            /* Check for @mention */
            char mention[256];
            snprintf(mention, sizeof(mention), "@%s", g_bot_username);
            if (strstr(text, mention)) {
                /* Strip the mention */
                char *cleaned = kelp_str_replace(text, mention, "");
                if (cleaned) {
                    /* We need the cleaned string to outlive this scope,
                     * but for simplicity, just use the original text */
                    free(cleaned);
                }
                msg = text;
            } else {
                return;  /* Not addressed to us */
            }
        } else {
            return;
        }
    }

    if (*msg == '\0')
        return;

    KELP_INFO("message from %s (%s) in chat %lld: %.80s%s",
               username ? username : (first_name ? first_name : "?"),
               chat_type ? chat_type : "?",
               (long long)chat_id, msg, strlen(msg) > 80 ? "..." : "");

    /* Show "typing..." */
    tg_send_chat_action(chat_id, "typing");

    /* Build string representations of chat_id and user_id for the gateway */
    char chat_id_str[32];
    snprintf(chat_id_str, sizeof(chat_id_str), "%lld", (long long)chat_id);

    char user_id_str[32];
    const char *user_id_ptr = NULL;
    if (from) {
        int64_t from_id = (int64_t)kelp_json_get_int(from, "id", 0);
        if (from_id != 0) {
            snprintf(user_id_str, sizeof(user_id_str), "%lld", (long long)from_id);
            user_id_ptr = user_id_str;
        }
    }

    /* Forward to gateway */
    char *response = gateway_chat(msg, chat_id_str, user_id_ptr);

    if (response && *response) {
        /* Telegram has a 4096 char limit per message */
        size_t resp_len = strlen(response);
        size_t offset = 0;

        while (offset < resp_len) {
            size_t chunk_len = resp_len - offset;
            if (chunk_len > 4000)
                chunk_len = 4000;

            char saved = response[offset + chunk_len];
            response[offset + chunk_len] = '\0';
            tg_send_message(chat_id, response + offset);
            response[offset + chunk_len] = saved;

            offset += chunk_len;
        }
    } else {
        tg_send_message(chat_id,
            "I'm having trouble connecting to the gateway. "
            "Please try again later.");
    }

    free(response);
}

/* ---- Long-polling loop -------------------------------------------------- */

static int poll_loop(void)
{
    KELP_INFO("starting long-poll loop (timeout=%ds)", POLL_TIMEOUT_SEC);

    while (!g_shutdown) {
        cJSON *params = cJSON_CreateObject();
        cJSON_AddNumberToObject(params, "offset", (double)g_update_offset);
        cJSON_AddNumberToObject(params, "timeout", POLL_TIMEOUT_SEC);
        cJSON_AddStringToObject(params, "allowed_updates",
                                "[\"message\"]");

        cJSON *updates = tg_api_call("getUpdates", params);
        cJSON_Delete(params);

        if (!updates) {
            if (g_shutdown)
                break;
            KELP_WARN("getUpdates failed, retrying in 5s...");
            sleep(5);
            continue;
        }

        int count = cJSON_GetArraySize(updates);
        if (count > 0)
            KELP_DEBUG("received %d update(s)", count);

        cJSON *update = NULL;
        cJSON_ArrayForEach(update, updates) {
            handle_update(update);
        }

        cJSON_Delete(updates);
    }

    return 0;
}

/* ---- Main --------------------------------------------------------------- */

static void print_usage(void)
{
    fprintf(stderr,
        "kelp-channel-telegram %s\n"
        "Usage: kelp-channel-telegram [options]\n"
        "\n"
        "Options:\n"
        "  -c, --config <path>   Config file\n"
        "  -t, --token <token>   Bot token (or set $TELEGRAM_BOT_TOKEN)\n"
        "  -s, --socket <path>   Gateway Unix socket path\n"
        "  -v, --verbose         Increase verbosity\n"
        "  -h, --help            Help\n",
        TELEGRAM_CHANNEL_VERSION);
}

int main(int argc, char *argv[])
{
    static struct option long_opts[] = {
        {"config",  required_argument, 0, 'c'},
        {"token",   required_argument, 0, 't'},
        {"socket",  required_argument, 0, 's'},
        {"verbose", no_argument,       0, 'v'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    const char *config_path = NULL;

    int opt;
    while ((opt = getopt_long(argc, argv, "c:t:s:vh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'c': config_path   = optarg; break;
        case 't': g_bot_token   = optarg; break;
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
    kelp_log_init("telegram", log_level);

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

    /* Resolve bot token */
    if (!g_bot_token)
        g_bot_token = getenv("TELEGRAM_BOT_TOKEN");
    if (!g_bot_token || *g_bot_token == '\0') {
        fprintf(stderr,
            "error: Telegram bot token required.\n"
            "Set TELEGRAM_BOT_TOKEN or use --token <token>\n");
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

    /* Init HTTP client */
    kelp_http_init();

    KELP_INFO("kelp-channel-telegram %s starting", TELEGRAM_CHANNEL_VERSION);
    KELP_INFO("gateway socket: %s", g_socket_path);

    /* Verify bot token by calling getMe */
    cJSON *me = tg_api_call("getMe", NULL);
    if (me) {
        const char *uname = kelp_json_get_string(me, "username");
        const char *fname = kelp_json_get_string(me, "first_name");
        if (uname)
            snprintf(g_bot_username, sizeof(g_bot_username), "%s", uname);
        KELP_INFO("logged in as @%s (%s)",
                   uname ? uname : "?", fname ? fname : "?");
        cJSON_Delete(me);
    } else {
        KELP_ERROR("getMe failed - check your bot token");
        kelp_http_cleanup();
        kelp_config_free(&g_cfg);
        return 1;
    }

    /* Main loop */
    poll_loop();

    /* Cleanup */
    kelp_http_cleanup();
    kelp_config_free(&g_cfg);

    KELP_INFO("kelp-channel-telegram exited cleanly");
    return 0;
}
