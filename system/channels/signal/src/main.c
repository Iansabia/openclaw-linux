/*
 * kelp-linux :: kelp-channel-signal
 * main.c - Signal channel plugin
 *
 * Interfaces with Signal via the signal-cli JSON-RPC interface (D-Bus or
 * TCP socket).  signal-cli must be installed and registered separately.
 * This plugin connects to signal-cli's JSON-RPC endpoint, listens for
 * incoming messages, forwards them to kelp-gateway, and sends responses
 * back via signal-cli.
 *
 * Usage: kelp-channel-signal [options]
 * Options:
 *   -c, --config <path>     Config file
 *   -a, --account <phone>   Signal account phone number (+1234567890)
 *   -e, --endpoint <addr>   signal-cli JSON-RPC endpoint (default: localhost:7583)
 *   -s, --socket <path>     Gateway Unix socket path
 *   -v, --verbose           Increase verbosity
 *   -h, --help              Help
 *
 * Prerequisites:
 *   - signal-cli installed and registered: signal-cli -a +1234567890 register
 *   - signal-cli running in JSON-RPC mode: signal-cli -a +1234567890 jsonRpc
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/kelp.h>
#include <kelp/config.h>

#include <cjson/cJSON.h>

#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

/* ---- Version ------------------------------------------------------------ */

#define SIGNAL_CHANNEL_VERSION "0.1.0"

/* ---- Defaults ----------------------------------------------------------- */

#define SIGNAL_CLI_HOST     "127.0.0.1"
#define SIGNAL_CLI_PORT     7583
#define RPC_BUF_SIZE        65536

/* ---- Global state ------------------------------------------------------- */

static kelp_config_t        g_cfg;
static const char           *g_account       = NULL;
static const char           *g_signal_host   = SIGNAL_CLI_HOST;
static int                   g_signal_port   = SIGNAL_CLI_PORT;
static const char           *g_socket_path   = NULL;
static int                   g_verbose       = 0;
static volatile sig_atomic_t g_shutdown      = 0;

/* signal-cli connection */
static int                   g_signal_fd     = -1;

/* ---- Signal handling ---------------------------------------------------- */

static void on_signal_handler(int signo)
{
    (void)signo;
    g_shutdown = 1;
}

/* ---- signal-cli TCP connection ------------------------------------------ */

static int signal_cli_connect(const char *host, int port)
{
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int err = getaddrinfo(host, port_str, &hints, &res);
    if (err != 0) {
        KELP_ERROR("getaddrinfo(%s:%d): %s", host, port, gai_strerror(err));
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
        KELP_ERROR("signal_cli_connect(%s:%d): connection failed", host, port);
        return -1;
    }

    KELP_INFO("connected to signal-cli at %s:%d", host, port);
    return fd;
}

/* ---- signal-cli JSON-RPC ------------------------------------------------ */

static int signal_rpc_id = 1;

static int signal_cli_send(int fd, const char *method, cJSON *params)
{
    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "jsonrpc", "2.0");
    cJSON_AddNumberToObject(req, "id", signal_rpc_id++);
    cJSON_AddStringToObject(req, "method", method);
    if (params)
        cJSON_AddItemToObject(req, "params", cJSON_Duplicate(params, 1));

    char *payload = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);
    if (!payload)
        return -1;

    size_t plen = strlen(payload);
    char *sendbuf = malloc(plen + 2);
    if (!sendbuf) {
        free(payload);
        return -1;
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
            return -1;
        }
        sent += n;
    }
    free(sendbuf);
    return 0;
}

static int signal_send_message(const char *recipient, const char *text)
{
    cJSON *params = cJSON_CreateObject();
    if (g_account)
        cJSON_AddStringToObject(params, "account", g_account);
    cJSON_AddStringToObject(params, "message", text);

    /* recipient can be a phone number or group ID */
    if (recipient[0] == '+') {
        cJSON *recipients = cJSON_AddArrayToObject(params, "recipients");
        cJSON_AddItemToArray(recipients, cJSON_CreateString(recipient));
    } else {
        cJSON_AddStringToObject(params, "groupId", recipient);
    }

    int ret = signal_cli_send(g_signal_fd, "send", params);
    cJSON_Delete(params);
    return ret;
}

/* ---- Gateway Unix socket (JSON-RPC) ------------------------------------- */

static char *gateway_chat(const char *message, const char *channel_id,
                          const char *user_id)
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

/* ---- Message handling --------------------------------------------------- */

static void handle_signal_message(cJSON *msg)
{
    /*
     * signal-cli JSON-RPC notifications look like:
     * {"jsonrpc":"2.0","method":"receive","params":{"envelope":{...}}}
     */
    const char *method = kelp_json_get_string(msg, "method");
    if (!method || strcmp(method, "receive") != 0)
        return;

    cJSON *params = kelp_json_get_object(msg, "params");
    if (!params)
        return;

    cJSON *envelope = kelp_json_get_object(params, "envelope");
    if (!envelope)
        return;

    const char *source = kelp_json_get_string(envelope, "sourceNumber");
    const char *source_name = kelp_json_get_string(envelope, "sourceName");

    /* Check for data message (regular text message) */
    cJSON *data_msg = kelp_json_get_object(envelope, "dataMessage");
    if (!data_msg)
        return;

    const char *text = kelp_json_get_string(data_msg, "message");
    if (!text || *text == '\0')
        return;

    /* Determine the reply destination */
    const char *reply_to = NULL;
    cJSON *group_info = kelp_json_get_object(data_msg, "groupInfo");
    if (group_info) {
        reply_to = kelp_json_get_string(group_info, "groupId");
    }
    if (!reply_to)
        reply_to = source;

    if (!reply_to)
        return;

    /* Ignore our own account */
    if (g_account && source && strcmp(source, g_account) == 0)
        return;

    KELP_INFO("message from %s (%s): %.80s%s",
               source ? source : "?",
               source_name ? source_name : "?",
               text, strlen(text) > 80 ? "..." : "");

    /* Forward to gateway */
    char *response = gateway_chat(text, reply_to, source);

    if (response && *response) {
        signal_send_message(reply_to, response);
    } else {
        signal_send_message(reply_to,
            "I'm having trouble connecting to the gateway. "
            "Please try again later.");
    }
    free(response);
}

/* ---- Main receive loop -------------------------------------------------- */

static int receive_loop(void)
{
    KELP_INFO("entering receive loop");

    /* Subscribe to receive notifications */
    if (g_account) {
        cJSON *params = cJSON_CreateObject();
        cJSON_AddStringToObject(params, "account", g_account);
        signal_cli_send(g_signal_fd, "subscribeReceive", params);
        cJSON_Delete(params);
    }

    kelp_str_t linebuf = kelp_str_new();
    char buf[RPC_BUF_SIZE];

    while (!g_shutdown) {
        struct pollfd pfd = {
            .fd     = g_signal_fd,
            .events = POLLIN
        };

        int ret = poll(&pfd, 1, 1000);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            KELP_ERROR("poll: %s", strerror(errno));
            break;
        }

        if (ret == 0)
            continue;

        if (pfd.revents & (POLLERR | POLLHUP)) {
            KELP_WARN("signal-cli connection lost");
            break;
        }

        ssize_t n = read(g_signal_fd, buf, sizeof(buf) - 1);
        if (n <= 0) {
            KELP_WARN("signal-cli connection closed");
            break;
        }
        buf[n] = '\0';
        kelp_str_append(&linebuf, buf, (size_t)n);

        /* Process complete lines */
        while (linebuf.data) {
            char *nl = strchr(linebuf.data, '\n');
            if (!nl)
                break;

            *nl = '\0';

            cJSON *msg = cJSON_Parse(linebuf.data);
            if (msg) {
                handle_signal_message(msg);
                cJSON_Delete(msg);
            }

            /* Shift remaining data */
            size_t consumed = (size_t)(nl - linebuf.data) + 1;
            size_t remaining = linebuf.len - consumed;
            if (remaining > 0)
                memmove(linebuf.data, nl + 1, remaining);
            linebuf.len = remaining;
            linebuf.data[linebuf.len] = '\0';
        }
    }

    kelp_str_free(&linebuf);
    return 0;
}

/* ---- Main --------------------------------------------------------------- */

static void print_usage(void)
{
    fprintf(stderr,
        "kelp-channel-signal %s\n"
        "Usage: kelp-channel-signal [options]\n"
        "\n"
        "Options:\n"
        "  -c, --config <path>     Config file\n"
        "  -a, --account <phone>   Signal account (+1234567890)\n"
        "  -e, --endpoint <h:p>    signal-cli endpoint (default: %s:%d)\n"
        "  -s, --socket <path>     Gateway Unix socket path\n"
        "  -v, --verbose           Increase verbosity\n"
        "  -h, --help              Help\n"
        "\n"
        "Environment:\n"
        "  SIGNAL_ACCOUNT          Phone number for Signal account\n"
        "  SIGNAL_CLI_HOST         signal-cli host (default: 127.0.0.1)\n"
        "  SIGNAL_CLI_PORT         signal-cli port (default: 7583)\n",
        SIGNAL_CHANNEL_VERSION, SIGNAL_CLI_HOST, SIGNAL_CLI_PORT);
}

int main(int argc, char *argv[])
{
    static struct option long_opts[] = {
        {"config",   required_argument, 0, 'c'},
        {"account",  required_argument, 0, 'a'},
        {"endpoint", required_argument, 0, 'e'},
        {"socket",   required_argument, 0, 's'},
        {"verbose",  no_argument,       0, 'v'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    const char *config_path = NULL;
    const char *endpoint = NULL;

    int opt;
    while ((opt = getopt_long(argc, argv, "c:a:e:s:vh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'c': config_path   = optarg; break;
        case 'a': g_account     = optarg; break;
        case 'e': endpoint      = optarg; break;
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
    kelp_log_init("signal", log_level);

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

    /* Resolve account */
    if (!g_account)
        g_account = getenv("SIGNAL_ACCOUNT");

    /* Resolve endpoint */
    if (endpoint) {
        /* Parse host:port */
        char *colon = strrchr(endpoint, ':');
        if (colon) {
            static char host_buf[256];
            size_t hlen = (size_t)(colon - endpoint);
            if (hlen >= sizeof(host_buf))
                hlen = sizeof(host_buf) - 1;
            memcpy(host_buf, endpoint, hlen);
            host_buf[hlen] = '\0';
            g_signal_host = host_buf;
            g_signal_port = atoi(colon + 1);
        } else {
            g_signal_host = endpoint;
        }
    } else {
        const char *env_host = getenv("SIGNAL_CLI_HOST");
        const char *env_port = getenv("SIGNAL_CLI_PORT");
        if (env_host)
            g_signal_host = env_host;
        if (env_port)
            g_signal_port = atoi(env_port);
    }

    /* Resolve gateway socket path */
    if (!g_socket_path)
        g_socket_path = g_cfg.gateway.socket_path;
    if (!g_socket_path)
        g_socket_path = "/run/kelp/gateway.sock";

    /* Signal handling */
    signal(SIGINT,  on_signal_handler);
    signal(SIGTERM, on_signal_handler);
    signal(SIGPIPE, SIG_IGN);

    KELP_INFO("kelp-channel-signal %s starting", SIGNAL_CHANNEL_VERSION);
    if (g_account)
        KELP_INFO("account: %s", g_account);
    KELP_INFO("signal-cli endpoint: %s:%d", g_signal_host, g_signal_port);
    KELP_INFO("gateway socket: %s", g_socket_path);

    /* Reconnect loop */
    int backoff = 1;
    while (!g_shutdown) {
        g_signal_fd = signal_cli_connect(g_signal_host, g_signal_port);
        if (g_signal_fd < 0) {
            KELP_ERROR("cannot connect to signal-cli, retrying in %ds", backoff);
            sleep(backoff);
            if (backoff < 60)
                backoff *= 2;
            continue;
        }

        backoff = 1;
        receive_loop();

        close(g_signal_fd);
        g_signal_fd = -1;

        if (g_shutdown)
            break;

        KELP_INFO("reconnecting in 5s...");
        sleep(5);
    }

    /* Cleanup */
    if (g_signal_fd >= 0)
        close(g_signal_fd);
    kelp_config_free(&g_cfg);

    KELP_INFO("kelp-channel-signal exited cleanly");
    return 0;
}
