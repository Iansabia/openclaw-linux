/*
 * clawd-linux :: clawd
 * main.c - CLI binary with getopt_long + subcommand dispatch
 *
 * Usage: clawd [options] <command> [args...]
 * Commands:
 *   chat      - Start interactive chat session
 *   ask       - Ask a single question
 *   gateway   - Gateway server management (run, status, stop)
 *   config    - Configuration management (show, set, get, edit)
 *   daemon    - Daemon management (install, start, stop, status)
 *   kernel    - Kernel module management (status, stats, load, unload)
 *   version   - Show version information
 *   help      - Show help
 *
 * Global options:
 *   -c, --config <path>   Config file path
 *   -p, --profile <name>  Config profile
 *   -v, --verbose         Increase verbosity
 *   -q, --quiet           Quiet mode
 *   --no-color            Disable color output
 *   -h, --help            Show help
 *   -V, --version         Show version
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/clawd.h>
#include <clawd/config.h>
#include <clawd/paths.h>
#include <clawd/ansi.h>
#include <clawd/kernel.h>

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <fcntl.h>
#include <poll.h>

#include <readline/readline.h>
#include <readline/history.h>

#include <cjson/cJSON.h>

/* ---- Version info ------------------------------------------------------- */

#define CLAWD_VERSION_STRING "0.1.0"

#ifndef CLAWD_BUILD_DATE
#define CLAWD_BUILD_DATE __DATE__
#endif

#ifndef CLAWD_BUILD_COMMIT
#define CLAWD_BUILD_COMMIT "unknown"
#endif

/* ---- Global state ------------------------------------------------------- */

static clawd_config_t g_cfg;
static const char    *g_config_path  = NULL;
static const char    *g_profile      = NULL;
static int            g_verbose      = 0;
static bool           g_quiet        = false;
static bool           g_color        = true;
static volatile sig_atomic_t g_quit  = 0;

/* ---- Forward declarations ----------------------------------------------- */

static int  cmd_chat(int argc, char **argv);
static int  cmd_ask(int argc, char **argv);
static int  cmd_gateway(int argc, char **argv);
static int  cmd_config(int argc, char **argv);
static int  cmd_daemon(int argc, char **argv);
static int  cmd_kernel(int argc, char **argv);
static int  cmd_version(int argc, char **argv);
static int  cmd_help(int argc, char **argv);

/* ---- Signal handler ----------------------------------------------------- */

static void sigint_handler(int signo)
{
    (void)signo;
    g_quit = 1;
}

/* ---- Unix socket helpers ------------------------------------------------ */

/**
 * Connect to the gateway over a Unix domain socket.
 * Returns the socket fd on success, -1 on error.
 */
static int gateway_connect(const char *socket_path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        if (!g_quiet)
            fprintf(stderr, "clawd: socket(): %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (!g_quiet)
            fprintf(stderr, "clawd: cannot connect to gateway at %s: %s\n",
                    socket_path, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

/**
 * Send a JSON-RPC request over the socket and return the full response.
 * Caller must free the returned string.
 */
static char *gateway_rpc(int fd, const char *method, cJSON *params)
{
    static int rpc_id = 1;

    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "jsonrpc", "2.0");
    cJSON_AddNumberToObject(req, "id", rpc_id++);
    cJSON_AddStringToObject(req, "method", method);
    if (params)
        cJSON_AddItemToObject(req, "params", cJSON_Duplicate(params, 1));

    char *payload = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);
    if (!payload)
        return NULL;

    /* Send with newline delimiter. */
    size_t plen = strlen(payload);
    char *sendbuf = malloc(plen + 2);
    if (!sendbuf) {
        free(payload);
        return NULL;
    }
    memcpy(sendbuf, payload, plen);
    sendbuf[plen]     = '\n';
    sendbuf[plen + 1] = '\0';
    free(payload);

    ssize_t sent = 0;
    ssize_t total = (ssize_t)(plen + 1);
    while (sent < total) {
        ssize_t n = write(fd, sendbuf + sent, (size_t)(total - sent));
        if (n <= 0) {
            free(sendbuf);
            return NULL;
        }
        sent += n;
    }
    free(sendbuf);

    /* Read response (newline-delimited JSON). */
    clawd_str_t resp = clawd_str_new();
    char buf[4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n <= 0)
            break;
        buf[n] = '\0';
        clawd_str_append(&resp, buf, (size_t)n);
        /* Check if we have a complete line. */
        if (resp.len > 0 && resp.data[resp.len - 1] == '\n')
            break;
    }

    if (resp.len == 0) {
        clawd_str_free(&resp);
        return NULL;
    }

    /* Trim trailing newline. */
    clawd_str_trim(&resp);

    /* Detach the buffer. */
    char *result = resp.data;
    resp.data = NULL;
    resp.len  = 0;
    resp.cap  = 0;
    return result;
}

/**
 * Send a JSON-RPC request for a chat message.
 * This is a lower-level helper that sends the request but does not read the
 * response, allowing the caller to handle streaming reads separately.
 *
 * Returns 0 on success, -1 on error.
 */
static int gateway_send_chat_request(int fd, const char *message, bool stream)
{
    static int rpc_id = 1000;

    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "message", message);
    cJSON_AddBoolToObject(params, "stream", stream);

    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "jsonrpc", "2.0");
    cJSON_AddNumberToObject(req, "id", rpc_id++);
    cJSON_AddStringToObject(req, "method", "chat.send");
    cJSON_AddItemToObject(req, "params", params);

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

    ssize_t sent = 0;
    ssize_t total = (ssize_t)(plen + 1);
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

/**
 * Read streaming token chunks from the gateway and print them to stdout.
 *
 * The gateway sends newline-delimited JSON chunks.  Each chunk is either:
 *   - A streaming delta:  {"type":"delta","content":"..."}
 *   - A done sentinel:    {"type":"done"}  or the literal string [DONE]
 *   - A complete JSON-RPC response (non-streaming fallback)
 *
 * Uses poll() with a timeout to avoid blocking indefinitely.
 *
 * Returns 0 on success, -1 on error.
 */
static int gateway_read_streaming(int fd)
{
    bool got_output   = false;
    bool style_active = false;

    /* Apply styling for the entire streamed response. */
    if (g_color && clawd_ansi_is_tty(stdout)) {
        clawd_ansi_style(stdout, CLAWD_STYLE_BOLD);
        clawd_ansi_color(stdout, CLAWD_COLOR_BRIGHT_WHITE);
        style_active = true;
    }

    /* Line buffer: accumulate bytes until we see a newline. */
    clawd_str_t linebuf = clawd_str_new();
    char readbuf[4096];
    int  rc = 0;

    struct pollfd pfd;
    pfd.fd     = fd;
    pfd.events = POLLIN;

    for (;;) {
        /* Poll with a 30-second timeout. */
        int prc = poll(&pfd, 1, 30000);
        if (prc < 0) {
            if (errno == EINTR)
                continue;
            if (!g_quiet)
                fprintf(stderr, "clawd: poll(): %s\n", strerror(errno));
            rc = -1;
            break;
        }
        if (prc == 0) {
            /* Timeout waiting for data. */
            if (!g_quiet)
                fprintf(stderr, "\nclawd: timeout waiting for gateway response\n");
            rc = -1;
            break;
        }

        ssize_t n = read(fd, readbuf, sizeof(readbuf) - 1);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            if (!g_quiet)
                fprintf(stderr, "clawd: read(): %s\n", strerror(errno));
            rc = -1;
            break;
        }
        if (n == 0) {
            /* EOF -- gateway closed the connection. */
            break;
        }

        /* Append to line buffer and process complete lines. */
        clawd_str_append(&linebuf, readbuf, (size_t)n);

        /* Process each newline-delimited chunk in the buffer. */
        char *start = linebuf.data;
        char *nl;
        while ((nl = strchr(start, '\n')) != NULL) {
            *nl = '\0';

            /* Skip empty lines. */
            if (*start == '\0') {
                start = nl + 1;
                continue;
            }

            /* Check for [DONE] sentinel. */
            if (strcmp(start, "[DONE]") == 0) {
                start = nl + 1;
                goto done;
            }

            /* Parse the JSON chunk. */
            cJSON *chunk = clawd_json_parse(start);
            if (!chunk) {
                /* Unparseable line -- skip it. */
                start = nl + 1;
                continue;
            }

            /* Check for a streaming delta. */
            const char *type = clawd_json_get_string(chunk, "type");
            if (type && strcmp(type, "done") == 0) {
                cJSON_Delete(chunk);
                start = nl + 1;
                goto done;
            }

            if (type && strcmp(type, "delta") == 0) {
                const char *content = clawd_json_get_string(chunk, "content");
                if (content) {
                    fputs(content, stdout);
                    fflush(stdout);
                    got_output = true;
                }
                cJSON_Delete(chunk);
                start = nl + 1;
                continue;
            }

            /* Check for error in a streaming chunk. */
            if (type && strcmp(type, "error") == 0) {
                const char *emsg = clawd_json_get_string(chunk, "message");
                fprintf(stderr, "clawd: stream error: %s\n",
                        emsg ? emsg : "unknown");
                cJSON_Delete(chunk);
                rc = -1;
                start = nl + 1;
                goto done;
            }

            /*
             * Fallback: this might be a complete JSON-RPC response
             * (non-streaming mode).  Handle it like the old code path.
             */
            cJSON *error_obj = cJSON_GetObjectItem(chunk, "error");
            if (error_obj) {
                const char *msg = clawd_json_get_string(error_obj, "message");
                fprintf(stderr, "clawd: gateway error: %s\n",
                        msg ? msg : "unknown");
                cJSON_Delete(chunk);
                rc = -1;
                start = nl + 1;
                goto done;
            }

            cJSON *result = cJSON_GetObjectItem(chunk, "result");
            if (result) {
                const char *text = clawd_json_get_string(result, "content");
                if (text) {
                    fputs(text, stdout);
                    fflush(stdout);
                    got_output = true;
                }
                cJSON_Delete(chunk);
                start = nl + 1;
                goto done;
            }

            cJSON_Delete(chunk);
            start = nl + 1;
        }

        /* Compact the line buffer: move remaining data to front. */
        if (start != linebuf.data) {
            size_t remaining = (size_t)(linebuf.data + linebuf.len - start);
            if (remaining > 0)
                memmove(linebuf.data, start, remaining);
            linebuf.len = remaining;
            linebuf.data[linebuf.len] = '\0';
        }
    }

done:
    if (style_active)
        clawd_ansi_reset(stdout);
    if (got_output)
        fputc('\n', stdout);
    fflush(stdout);
    clawd_str_free(&linebuf);
    return rc;
}

/**
 * Send a chat message via JSON-RPC and display the response.
 *
 * When @p stream_to_stdout is true, reads the response incrementally as
 * newline-delimited JSON chunks (one per token/event) and prints each
 * content delta immediately to stdout with fflush() for real-time display.
 *
 * When @p stream_to_stdout is false, falls back to a single blocking
 * gateway_rpc() call and prints the complete result.
 *
 * Returns 0 on success, -1 on error.
 */
static int gateway_chat(int fd, const char *message, bool stream_to_stdout)
{
    if (stream_to_stdout) {
        /* Streaming mode: send request, then incrementally read chunks. */
        if (gateway_send_chat_request(fd, message, true) != 0) {
            if (!g_quiet)
                fprintf(stderr, "clawd: failed to send request\n");
            return -1;
        }
        return gateway_read_streaming(fd);
    }

    /* Non-streaming mode: use the blocking RPC helper. */
    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "message", message);
    cJSON_AddBoolToObject(params, "stream", false);

    char *resp_str = gateway_rpc(fd, "chat.send", params);
    cJSON_Delete(params);

    if (!resp_str) {
        if (!g_quiet)
            fprintf(stderr, "clawd: no response from gateway\n");
        return -1;
    }

    /* Parse JSON-RPC response. */
    cJSON *resp = clawd_json_parse(resp_str);
    free(resp_str);
    if (!resp) {
        if (!g_quiet)
            fprintf(stderr, "clawd: failed to parse response\n");
        return -1;
    }

    cJSON *error = cJSON_GetObjectItem(resp, "error");
    if (error) {
        const char *msg = clawd_json_get_string(error, "message");
        fprintf(stderr, "clawd: gateway error: %s\n", msg ? msg : "unknown");
        cJSON_Delete(resp);
        return -1;
    }

    cJSON *result = cJSON_GetObjectItem(resp, "result");
    if (result) {
        const char *text = clawd_json_get_string(result, "content");
        if (text) {
            if (g_color && clawd_ansi_is_tty(stdout)) {
                clawd_ansi_style(stdout, CLAWD_STYLE_BOLD);
                clawd_ansi_color(stdout, CLAWD_COLOR_BRIGHT_WHITE);
            }
            fputs(text, stdout);
            if (g_color && clawd_ansi_is_tty(stdout))
                clawd_ansi_reset(stdout);
            fputc('\n', stdout);
            fflush(stdout);
        }
    }

    cJSON_Delete(resp);
    return 0;
}

/* ---- Subcommand: chat --------------------------------------------------- */

static int cmd_chat(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    const char *sock_path = g_cfg.gateway.socket_path;
    if (!sock_path) {
        char *default_sock = clawd_paths_socket();
        if (!default_sock) {
            fprintf(stderr, "clawd: cannot determine socket path\n");
            return 1;
        }
        sock_path = default_sock;
    }

    int fd = gateway_connect(sock_path);
    if (fd < 0) {
        fprintf(stderr, "clawd: is the gateway running? "
                        "Start it with: clawd gateway run\n");
        return 1;
    }

    /* Install signal handler for clean exit. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);

    if (!g_quiet) {
        if (g_color && clawd_ansi_is_tty(stdout)) {
            clawd_ansi_style(stdout, CLAWD_STYLE_BOLD);
            clawd_ansi_color(stdout, CLAWD_COLOR_CYAN);
        }
        printf("clawd %s - interactive chat\n", CLAWD_VERSION_STRING);
        if (g_color && clawd_ansi_is_tty(stdout))
            clawd_ansi_reset(stdout);
        printf("Type your message and press Enter. Ctrl-C to quit.\n\n");
    }

    /* REPL loop. */
    for (;;) {
        if (g_quit)
            break;

        char *prompt = NULL;
        if (g_color && clawd_ansi_is_tty(stdin)) {
            prompt = "\033[1;32myou>\033[0m ";
        } else {
            prompt = "you> ";
        }

        char *line = readline(prompt);
        if (!line) {
            /* EOF (Ctrl-D). */
            if (!g_quiet)
                printf("\n");
            break;
        }

        /* Skip empty lines. */
        if (line[0] == '\0') {
            free(line);
            continue;
        }

        add_history(line);

        /* Special commands. */
        if (strcmp(line, "/quit") == 0 || strcmp(line, "/exit") == 0) {
            free(line);
            break;
        }
        if (strcmp(line, "/clear") == 0) {
            if (clawd_ansi_is_tty(stdout))
                clawd_ansi_clear_screen(stdout);
            free(line);
            continue;
        }
        if (strcmp(line, "/help") == 0) {
            printf("Chat commands:\n");
            printf("  /quit, /exit   - Exit chat\n");
            printf("  /clear         - Clear screen\n");
            printf("  /help          - Show this help\n");
            free(line);
            continue;
        }

        /* Print assistant label. */
        if (g_color && clawd_ansi_is_tty(stdout)) {
            printf("\033[1;37massistant>\033[0m ");
        } else {
            printf("assistant> ");
        }
        fflush(stdout);

        int rc = gateway_chat(fd, line, true);
        if (rc != 0) {
            if (g_color && clawd_ansi_is_tty(stdout))
                clawd_ansi_color(stdout, CLAWD_COLOR_RED);
            fprintf(stderr, "[error communicating with gateway]\n");
            if (g_color && clawd_ansi_is_tty(stdout))
                clawd_ansi_reset(stdout);
        }

        free(line);
    }

    close(fd);
    return 0;
}

/* ---- Subcommand: ask ---------------------------------------------------- */

static int cmd_ask(int argc, char **argv)
{
    /* Join all args into a question string (may be empty if piping). */
    clawd_str_t question = clawd_str_new();
    for (int i = 0; i < argc; i++) {
        if (i > 0)
            clawd_str_append_cstr(&question, " ");
        clawd_str_append_cstr(&question, argv[i]);
    }

    /*
     * If stdin is not a TTY (piped input), read all of stdin and append it
     * to the question.  This enables usage like:
     *   echo "explain this" | clawd ask
     *   cat file.c | clawd ask "review this code"
     */
    if (!isatty(STDIN_FILENO)) {
        clawd_str_t stdin_buf = clawd_str_new();
        char buf[4096];
        for (;;) {
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0)
                break;
            clawd_str_append(&stdin_buf, buf, (size_t)n);
        }

        if (stdin_buf.len > 0) {
            /* Separate the argv question from piped content. */
            if (question.len > 0)
                clawd_str_append_cstr(&question, "\n\n");
            clawd_str_append(&question, stdin_buf.data, stdin_buf.len);
        }
        clawd_str_free(&stdin_buf);
    }

    if (question.len == 0) {
        fprintf(stderr, "Usage: clawd ask <question>\n");
        fprintf(stderr, "       echo \"text\" | clawd ask\n");
        clawd_str_free(&question);
        return 1;
    }

    const char *sock_path = g_cfg.gateway.socket_path;
    if (!sock_path) {
        char *default_sock = clawd_paths_socket();
        if (!default_sock) {
            fprintf(stderr, "clawd: cannot determine socket path\n");
            clawd_str_free(&question);
            return 1;
        }
        sock_path = default_sock;
    }

    int fd = gateway_connect(sock_path);
    if (fd < 0) {
        fprintf(stderr, "clawd: is the gateway running? "
                        "Start it with: clawd gateway run\n");
        clawd_str_free(&question);
        return 1;
    }

    int rc = gateway_chat(fd, question.data, false);
    close(fd);
    clawd_str_free(&question);
    return rc == 0 ? 0 : 1;
}

/* ---- Subcommand: gateway ------------------------------------------------ */

static int gateway_is_running(const char *sock_path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
    return rc == 0;
}

static pid_t gateway_read_pid(const char *runtime_dir)
{
    char pidpath[512];
    snprintf(pidpath, sizeof(pidpath), "%s/clawd-gateway.pid", runtime_dir);

    FILE *f = fopen(pidpath, "r");
    if (!f)
        return -1;

    pid_t pid = 0;
    if (fscanf(f, "%d", &pid) != 1)
        pid = -1;
    fclose(f);

    /* Verify the process still exists. */
    if (pid > 0 && kill(pid, 0) != 0)
        pid = -1;

    return pid;
}

static int cmd_gateway(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "Usage: clawd gateway <run|status|stop>\n");
        return 1;
    }

    const char *subcmd = argv[0];

    char *runtime_dir = clawd_paths_runtime_dir();
    if (!runtime_dir) {
        fprintf(stderr, "clawd: cannot determine runtime directory\n");
        return 1;
    }

    char *sock_path = g_cfg.gateway.socket_path
                          ? strdup(g_cfg.gateway.socket_path)
                          : clawd_paths_socket();

    if (strcmp(subcmd, "run") == 0) {
        /* Start gateway in foreground by exec'ing clawd-gateway. */
        if (!g_quiet)
            printf("Starting clawd gateway...\n");

        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d",
                 g_cfg.gateway.port > 0 ? g_cfg.gateway.port : 3000);

        const char *host = g_cfg.gateway.host ? g_cfg.gateway.host : "127.0.0.1";

        /* Build argument list for exec. */
        const char *gw_args[16];
        int ai = 0;
        gw_args[ai++] = "clawd-gateway";
        gw_args[ai++] = "-l";
        gw_args[ai++] = host;
        gw_args[ai++] = "-p";
        gw_args[ai++] = port_str;
        if (sock_path) {
            gw_args[ai++] = "-s";
            gw_args[ai++] = sock_path;
        }
        if (g_config_path) {
            gw_args[ai++] = "-c";
            gw_args[ai++] = g_config_path;
        }
        gw_args[ai] = NULL;

        execvp("clawd-gateway", (char *const *)gw_args);
        fprintf(stderr, "clawd: failed to exec clawd-gateway: %s\n",
                strerror(errno));
        free(runtime_dir);
        free(sock_path);
        return 1;
    }

    if (strcmp(subcmd, "status") == 0) {
        if (gateway_is_running(sock_path)) {
            pid_t pid = gateway_read_pid(runtime_dir);
            printf("Gateway is running");
            if (pid > 0)
                printf(" (PID %d)", pid);
            printf(" on %s\n", sock_path);
            free(runtime_dir);
            free(sock_path);
            return 0;
        } else {
            printf("Gateway is not running\n");
            free(runtime_dir);
            free(sock_path);
            return 1;
        }
    }

    if (strcmp(subcmd, "stop") == 0) {
        pid_t pid = gateway_read_pid(runtime_dir);
        if (pid <= 0) {
            fprintf(stderr, "clawd: gateway does not appear to be running\n");
            free(runtime_dir);
            free(sock_path);
            return 1;
        }
        if (!g_quiet)
            printf("Sending SIGTERM to gateway (PID %d)...\n", pid);
        if (kill(pid, SIGTERM) != 0) {
            fprintf(stderr, "clawd: kill(%d, SIGTERM): %s\n",
                    pid, strerror(errno));
            free(runtime_dir);
            free(sock_path);
            return 1;
        }

        /* Wait briefly for the process to exit. */
        for (int i = 0; i < 30; i++) {
            usleep(100000); /* 100ms */
            if (kill(pid, 0) != 0) {
                if (!g_quiet)
                    printf("Gateway stopped.\n");
                free(runtime_dir);
                free(sock_path);
                return 0;
            }
        }
        fprintf(stderr, "clawd: gateway did not stop within 3 seconds\n");
        free(runtime_dir);
        free(sock_path);
        return 1;
    }

    fprintf(stderr, "clawd: unknown gateway command '%s'\n", subcmd);
    fprintf(stderr, "Usage: clawd gateway <run|status|stop>\n");
    free(runtime_dir);
    free(sock_path);
    return 1;
}

/* ---- Subcommand: config ------------------------------------------------- */

static int cmd_config(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "Usage: clawd config <show|set|get|edit>\n");
        return 1;
    }

    const char *subcmd = argv[0];

    if (strcmp(subcmd, "show") == 0) {
        /* Print all config fields as a readable table. */
        if (g_color && clawd_ansi_is_tty(stdout))
            clawd_ansi_style(stdout, CLAWD_STYLE_BOLD);
        printf("Configuration\n");
        if (g_color && clawd_ansi_is_tty(stdout))
            clawd_ansi_reset(stdout);
        printf("%-30s %s\n", "config_dir",
               g_cfg.config_dir ? g_cfg.config_dir : "(unset)");
        printf("%-30s %s\n", "data_dir",
               g_cfg.data_dir ? g_cfg.data_dir : "(unset)");
        printf("%-30s %s\n", "runtime_dir",
               g_cfg.runtime_dir ? g_cfg.runtime_dir : "(unset)");
        printf("%-30s %s\n", "profile",
               g_cfg.profile ? g_cfg.profile : "default");
        printf("\n");

        printf("%-30s %s\n", "gateway.host",
               g_cfg.gateway.host ? g_cfg.gateway.host : "127.0.0.1");
        printf("%-30s %d\n", "gateway.port",
               g_cfg.gateway.port > 0 ? g_cfg.gateway.port : 3000);
        printf("%-30s %s\n", "gateway.socket_path",
               g_cfg.gateway.socket_path ? g_cfg.gateway.socket_path : "(auto)");
        printf("%-30s %s\n", "gateway.tls_enabled",
               g_cfg.gateway.tls_enabled ? "true" : "false");
        printf("\n");

        printf("%-30s %s\n", "model.default_provider",
               g_cfg.model.default_provider ? g_cfg.model.default_provider
                                            : "anthropic");
        printf("%-30s %s\n", "model.default_model",
               g_cfg.model.default_model ? g_cfg.model.default_model
                                         : "(unset)");
        printf("%-30s %s\n", "model.api_key",
               g_cfg.model.api_key ? "***" : "(unset)");
        printf("%-30s %d\n", "model.max_tokens", g_cfg.model.max_tokens);
        printf("%-30s %.2f\n", "model.temperature", (double)g_cfg.model.temperature);
        printf("\n");

        printf("%-30s %s\n", "security.sandbox_enabled",
               g_cfg.security.sandbox_enabled ? "true" : "false");
        printf("%-30s %d\n", "logging.level", g_cfg.logging.level);
        printf("%-30s %s\n", "logging.file",
               g_cfg.logging.file ? g_cfg.logging.file : "(stderr)");
        return 0;
    }

    if (strcmp(subcmd, "get") == 0) {
        if (argc < 2) {
            fprintf(stderr, "Usage: clawd config get <key>\n");
            return 1;
        }
        const char *key = argv[1];
        const char *val = clawd_config_get_string(&g_cfg, key);
        if (val) {
            /* Redact the API key. */
            if (strcmp(key, "model.api_key") == 0)
                printf("***\n");
            else
                printf("%s\n", val);
            return 0;
        }
        /* Try integer / bool. */
        int ival = clawd_config_get_int(&g_cfg, key, INT32_MIN);
        if (ival != INT32_MIN) {
            printf("%d\n", ival);
            return 0;
        }
        fprintf(stderr, "clawd: unknown config key '%s'\n", key);
        return 1;
    }

    if (strcmp(subcmd, "set") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: clawd config set <key> <value>\n");
            return 1;
        }

        const char *key   = argv[1];
        const char *value = argv[2];

        char *config_dir = clawd_paths_config_dir();
        if (!config_dir) {
            fprintf(stderr, "clawd: cannot determine config directory\n");
            return 1;
        }

        /* Ensure the config directory exists before writing. */
        clawd_paths_ensure_dirs();

        /*
         * Determine the config file path and format.
         * Check for JSON first, fall back to YAML.
         */
        char filepath_json[512];
        char filepath_yaml[512];
        char filepath[512];
        snprintf(filepath_json, sizeof(filepath_json),
                 "%s/clawd.json", config_dir);
        snprintf(filepath_yaml, sizeof(filepath_yaml),
                 "%s/clawd.yaml", config_dir);
        free(config_dir);

        struct stat st;
        bool is_json = (stat(filepath_json, &st) == 0 && S_ISREG(st.st_mode));
        snprintf(filepath, sizeof(filepath), "%s",
                 is_json ? filepath_json : filepath_yaml);

        if (is_json) {
            /* ---- JSON config: parse with cJSON, modify, rewrite ---- */
            cJSON *root = NULL;

            FILE *rf = fopen(filepath, "r");
            if (rf) {
                fseek(rf, 0, SEEK_END);
                long fsize = ftell(rf);
                fseek(rf, 0, SEEK_SET);
                if (fsize > 0) {
                    char *json_str = malloc((size_t)fsize + 1);
                    if (json_str) {
                        size_t nread = fread(json_str, 1, (size_t)fsize, rf);
                        json_str[nread] = '\0';
                        root = cJSON_Parse(json_str);
                        free(json_str);
                    }
                }
                fclose(rf);
            }

            if (!root)
                root = cJSON_CreateObject();

            /*
             * Navigate / create nested objects for dotted key path.
             * E.g. "gateway.port" -> root["gateway"]["port"]
             */
            int nparts = 0;
            char **parts = clawd_str_split(key, '.', &nparts);
            if (parts && nparts > 0) {
                cJSON *node = root;
                for (int i = 0; i < nparts - 1; i++) {
                    cJSON *child = cJSON_GetObjectItem(node, parts[i]);
                    if (!child) {
                        child = cJSON_CreateObject();
                        cJSON_AddItemToObject(node, parts[i], child);
                    }
                    node = child;
                }

                /* Set the leaf value (auto-detect type). */
                const char *leaf = parts[nparts - 1];
                cJSON_DeleteItemFromObject(node, leaf);

                /* Try parsing as integer. */
                char *endp = NULL;
                long lval = strtol(value, &endp, 10);
                if (endp && *endp == '\0' && endp != value) {
                    cJSON_AddNumberToObject(node, leaf, (double)lval);
                } else if (strcmp(value, "true") == 0) {
                    cJSON_AddBoolToObject(node, leaf, 1);
                } else if (strcmp(value, "false") == 0) {
                    cJSON_AddBoolToObject(node, leaf, 0);
                } else {
                    cJSON_AddStringToObject(node, leaf, value);
                }

                for (int i = 0; i < nparts; i++)
                    free(parts[i]);
                free(parts);
            }

            /* Write the modified JSON back. */
            char *output = cJSON_Print(root);
            cJSON_Delete(root);
            if (!output) {
                fprintf(stderr, "clawd: failed to serialize config\n");
                return 1;
            }

            FILE *wf = fopen(filepath, "w");
            if (!wf) {
                fprintf(stderr, "clawd: cannot write %s: %s\n",
                        filepath, strerror(errno));
                free(output);
                return 1;
            }
            fputs(output, wf);
            fputc('\n', wf);
            fclose(wf);
            free(output);

        } else {
            /*
             * ---- YAML config: line-based in-place editing ----
             *
             * NOTE: A full YAML round-trip library (e.g. libyaml with
             * emitter, or a tree-preserving library like yaml-cpp) would be
             * ideal for production.  The approach below handles the common
             * case of simple "section.key: value" edits without destroying
             * comments or formatting, but it does not handle all YAML edge
             * cases (flow style, multi-line values, anchors, etc.).
             *
             * Strategy:
             *   - Split the dotted key into parts (e.g. "gateway" + "port").
             *   - Read the file line by line, tracking indentation depth.
             *   - Find the target section and key line, replace its value.
             *   - If the key does not exist, append properly indented YAML.
             */
            int nparts = 0;
            char **parts = clawd_str_split(key, '.', &nparts);
            if (!parts || nparts == 0) {
                fprintf(stderr, "clawd: invalid key '%s'\n", key);
                return 1;
            }

            /* Read existing file content (may not exist yet). */
            clawd_buf_t fbuf = clawd_buf_new(0);
            (void)clawd_buf_read_file(&fbuf, filepath);

            /* Split into lines. */
            clawd_str_t content_str = clawd_str_new();
            if (fbuf.len > 0)
                clawd_str_append(&content_str, (const char *)fbuf.data,
                                 fbuf.len);
            clawd_buf_free(&fbuf);

            /* Parse lines. */
            int line_count = 0;
            char **lines = clawd_str_split(
                content_str.data ? content_str.data : "", '\n', &line_count);
            clawd_str_free(&content_str);

            /*
             * Search for the target key by walking the YAML structure.
             * For a key like "gateway.port", we look for a line "gateway:"
             * at indent 0, then "port:" at indent 2 within that section.
             */
            bool found = false;
            int target_line = -1;
            int depth = 0;            /* current search depth in parts[] */
            int section_indent = -1;  /* indent of the current section   */

            for (int li = 0; li < line_count && !found; li++) {
                const char *ln = lines[li];

                /* Measure leading spaces. */
                int indent = 0;
                while (ln[indent] == ' ')
                    indent++;

                /* Skip blank lines and comments. */
                if (ln[indent] == '\0' || ln[indent] == '#')
                    continue;

                /* If we're inside a section and indent drops back, we left. */
                if (depth > 0 && indent <= section_indent) {
                    /* Reset: the section ended without finding the key. */
                    depth = 0;
                    section_indent = -1;
                }

                int expected_indent = depth * 2;

                if (indent == expected_indent) {
                    /* Build the pattern we're looking for. */
                    char pattern[256];
                    snprintf(pattern, sizeof(pattern), "%s:", parts[depth]);
                    size_t plen = strlen(pattern);

                    /* Check if this line starts with the pattern. */
                    if (strncmp(ln + indent, pattern, plen) == 0) {
                        char after = ln[indent + (int)plen];
                        if (after == ' ' || after == '\0' || after == '\n') {
                            if (depth == nparts - 1) {
                                /* Found the leaf key -- replace this line. */
                                target_line = li;
                                found = true;
                            } else {
                                /* Found an intermediate section -- go deeper. */
                                section_indent = indent;
                                depth++;
                            }
                        }
                    }
                }
            }

            /* Rebuild the file content. */
            clawd_str_t output = clawd_str_new();

            if (found && target_line >= 0) {
                /* Replace the target line. */
                for (int li = 0; li < line_count; li++) {
                    if (li == target_line) {
                        /* Preserve the original indentation. */
                        int indent = 0;
                        while (lines[li][indent] == ' ')
                            indent++;
                        for (int s = 0; s < indent; s++)
                            clawd_str_append_cstr(&output, " ");
                        clawd_str_printf(&output, "%s: %s",
                                         parts[nparts - 1], value);
                    } else {
                        clawd_str_append_cstr(&output, lines[li]);
                    }
                    /* Add newline between lines (not after last). */
                    if (li < line_count - 1)
                        clawd_str_append_cstr(&output, "\n");
                }
                /* Preserve trailing newline if the original had one. */
                if (line_count > 0 && lines[line_count - 1][0] == '\0')
                    clawd_str_append_cstr(&output, "\n");
            } else {
                /* Key not found: keep existing content and append. */
                for (int li = 0; li < line_count; li++) {
                    clawd_str_append_cstr(&output, lines[li]);
                    if (li < line_count - 1)
                        clawd_str_append_cstr(&output, "\n");
                }

                /* Ensure a trailing newline before appending. */
                if (output.len > 0 &&
                    output.data[output.len - 1] != '\n')
                    clawd_str_append_cstr(&output, "\n");

                clawd_str_append_cstr(&output, "\n");
                clawd_str_printf(&output,
                    "# Set by 'clawd config set %s %s'\n", key, value);

                /* Write the nested YAML with proper indentation. */
                for (int i = 0; i < nparts; i++) {
                    for (int j = 0; j < i; j++)
                        clawd_str_append_cstr(&output, "  ");
                    if (i < nparts - 1)
                        clawd_str_printf(&output, "%s:\n", parts[i]);
                    else
                        clawd_str_printf(&output, "%s: %s\n", parts[i],
                                         value);
                }
            }

            /* Free the split lines. */
            for (int li = 0; li < line_count; li++)
                free(lines[li]);
            free(lines);
            for (int i = 0; i < nparts; i++)
                free(parts[i]);
            free(parts);

            /* Write the output file. */
            FILE *wf = fopen(filepath, "w");
            if (!wf) {
                fprintf(stderr, "clawd: cannot write %s: %s\n",
                        filepath, strerror(errno));
                clawd_str_free(&output);
                return 1;
            }
            if (output.len > 0)
                fwrite(output.data, 1, output.len, wf);
            fclose(wf);
            clawd_str_free(&output);
        }

        if (!g_quiet)
            printf("Set %s = %s in %s\n", key, value, filepath);
        return 0;
    }

    if (strcmp(subcmd, "edit") == 0) {
        const char *editor = getenv("EDITOR");
        if (!editor)
            editor = getenv("VISUAL");
        if (!editor)
            editor = "vi";

        char *config_dir = clawd_paths_config_dir();
        if (!config_dir) {
            fprintf(stderr, "clawd: cannot determine config directory\n");
            return 1;
        }

        /* Ensure the config directory exists. */
        clawd_paths_ensure_dirs();

        char filepath[512];
        snprintf(filepath, sizeof(filepath), "%s/clawd.yaml", config_dir);
        free(config_dir);

        /* Create the file if it does not exist. */
        FILE *f = fopen(filepath, "a");
        if (f)
            fclose(f);

        if (!g_quiet)
            printf("Opening %s with %s...\n", filepath, editor);

        execlp(editor, editor, filepath, (char *)NULL);
        fprintf(stderr, "clawd: failed to exec %s: %s\n",
                editor, strerror(errno));
        return 1;
    }

    fprintf(stderr, "clawd: unknown config command '%s'\n", subcmd);
    fprintf(stderr, "Usage: clawd config <show|set|get|edit>\n");
    return 1;
}

/* ---- Subcommand: daemon ------------------------------------------------- */

static int cmd_daemon(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr,
                "Usage: clawd daemon <install|uninstall|start|stop|restart|"
                "status|logs|enable|disable>\n");
        return 1;
    }

    const char *subcmd = argv[0];

#ifdef __linux__
    /* On Linux, delegate to clawd-daemon binary which handles systemd. */
    const char *daemon_args[16];
    int ai = 0;
    daemon_args[ai++] = "clawd-daemon";
    daemon_args[ai++] = subcmd;
    if (g_config_path) {
        daemon_args[ai++] = "-c";
        daemon_args[ai++] = g_config_path;
    }
    daemon_args[ai] = NULL;

    execvp("clawd-daemon", (char *const *)daemon_args);
    fprintf(stderr, "clawd: failed to exec clawd-daemon: %s\n",
            strerror(errno));
    return 1;
#else
    /* On non-Linux (macOS), provide a launchd-based fallback. */
    if (strcmp(subcmd, "status") == 0) {
        char *sock_path = g_cfg.gateway.socket_path
                              ? strdup(g_cfg.gateway.socket_path)
                              : clawd_paths_socket();
        if (gateway_is_running(sock_path)) {
            printf("Gateway is running\n");
            free(sock_path);
            return 0;
        } else {
            printf("Gateway is not running\n");
            free(sock_path);
            return 1;
        }
    }

    if (strcmp(subcmd, "install") == 0) {
        /* Generate a launchd plist. */
        const char *home = getenv("HOME");
        if (!home) {
            fprintf(stderr, "clawd: $HOME not set\n");
            return 1;
        }

        char plist_dir[512];
        snprintf(plist_dir, sizeof(plist_dir),
                 "%s/Library/LaunchAgents", home);

        char plist_path[512];
        snprintf(plist_path, sizeof(plist_path),
                 "%s/dev.clawd.gateway.plist", plist_dir);

        FILE *f = fopen(plist_path, "w");
        if (!f) {
            fprintf(stderr, "clawd: cannot create %s: %s\n",
                    plist_path, strerror(errno));
            return 1;
        }

        fprintf(f,
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\"\n"
                "  \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                "<plist version=\"1.0\">\n"
                "<dict>\n"
                "  <key>Label</key>\n"
                "  <string>dev.clawd.gateway</string>\n"
                "  <key>ProgramArguments</key>\n"
                "  <array>\n"
                "    <string>/usr/local/bin/clawd-gateway</string>\n"
                "  </array>\n"
                "  <key>RunAtLoad</key>\n"
                "  <false/>\n"
                "  <key>KeepAlive</key>\n"
                "  <dict>\n"
                "    <key>SuccessfulExit</key>\n"
                "    <false/>\n"
                "  </dict>\n"
                "  <key>StandardOutPath</key>\n"
                "  <string>/tmp/clawd-gateway.log</string>\n"
                "  <key>StandardErrorPath</key>\n"
                "  <string>/tmp/clawd-gateway.log</string>\n"
                "</dict>\n"
                "</plist>\n");
        fclose(f);

        printf("Installed launchd plist: %s\n", plist_path);
        return 0;
    }

    if (strcmp(subcmd, "start") == 0) {
        int rc = system("launchctl load ~/Library/LaunchAgents/dev.clawd.gateway.plist 2>/dev/null || "
                        "launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.clawd.gateway.plist");
        return rc == 0 ? 0 : 1;
    }

    if (strcmp(subcmd, "stop") == 0) {
        int rc = system("launchctl unload ~/Library/LaunchAgents/dev.clawd.gateway.plist 2>/dev/null || "
                        "launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/dev.clawd.gateway.plist");
        return rc == 0 ? 0 : 1;
    }

    fprintf(stderr, "clawd: daemon command '%s' is only fully supported on Linux\n",
            subcmd);
    return 1;
#endif
}

/* ---- Subcommand: kernel ------------------------------------------------- */

static int cmd_kernel(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr,
                "Usage: clawd kernel <status|stats|load|unload>\n");
        return 1;
    }

    const char *subcmd = argv[0];

    if (strcmp(subcmd, "status") == 0) {
        if (!clawd_kernel_available()) {
            printf("Kernel module: not loaded\n");
            printf("  /dev/clawd is not available.\n");
            printf("  Load with: sudo insmod clawd.ko\n");
            return 1;
        }

        int fd = clawd_kernel_open();
        if (fd < 0) {
            fprintf(stderr, "clawd: cannot open /dev/clawd: %s\n",
                    strerror(errno));
            return 1;
        }

        struct clawd_kversion ver;
        if (clawd_kernel_get_version(fd, &ver) == 0) {
            printf("Kernel module: loaded\n");
            printf("  Version: %u.%u.%u\n", ver.major, ver.minor, ver.patch);
            printf("  Build:   %s\n", ver.build);
        }

        struct clawd_kstatus st;
        if (clawd_kernel_get_status(fd, &st) == 0) {
            printf("  Netfilter: %s\n", st.netfilter_enabled ? "enabled" : "disabled");
            printf("  Log level: %d\n", st.log_level);
            printf("  Open handles: %d\n", st.chardev_open_count);
        }

        clawd_kernel_close(fd);
        return 0;
    }

    if (strcmp(subcmd, "stats") == 0) {
        if (!clawd_kernel_available()) {
            fprintf(stderr, "clawd: kernel module not loaded\n");
            return 1;
        }

        int fd = clawd_kernel_open();
        if (fd < 0) {
            fprintf(stderr, "clawd: cannot open /dev/clawd: %s\n",
                    strerror(errno));
            return 1;
        }

        struct clawd_kstats stats;
        if (clawd_kernel_get_stats(fd, &stats) == 0) {
            uint64_t h = stats.uptime_seconds / 3600;
            uint64_t m = (stats.uptime_seconds % 3600) / 60;
            uint64_t s = stats.uptime_seconds % 60;

            printf("Clawd Kernel Stats\n");
            printf("==================\n");
            printf("Uptime:              %lluh%llum%llus\n",
                   (unsigned long long)h, (unsigned long long)m,
                   (unsigned long long)s);
            printf("Messages processed:  %llu\n",
                   (unsigned long long)stats.messages_processed);
            printf("Bytes read:          %llu\n",
                   (unsigned long long)stats.bytes_read);
            printf("Bytes written:       %llu\n",
                   (unsigned long long)stats.bytes_written);
            printf("Active sessions:     %llu\n",
                   (unsigned long long)stats.active_sessions);
            printf("Netfilter packets:   %llu\n",
                   (unsigned long long)stats.netfilter_packets);
            printf("Netfilter blocked:   %llu\n",
                   (unsigned long long)stats.netfilter_blocked);
        } else {
            fprintf(stderr, "clawd: failed to get stats: %s\n",
                    strerror(errno));
            clawd_kernel_close(fd);
            return 1;
        }

        clawd_kernel_close(fd);
        return 0;
    }

    if (strcmp(subcmd, "load") == 0) {
        if (clawd_kernel_available()) {
            printf("Kernel module is already loaded.\n");
            return 0;
        }
        printf("Loading clawd kernel module...\n");
        int rc = system("sudo modprobe clawd 2>/dev/null || sudo insmod clawd.ko");
        return rc == 0 ? 0 : 1;
    }

    if (strcmp(subcmd, "unload") == 0) {
        if (!clawd_kernel_available()) {
            printf("Kernel module is not loaded.\n");
            return 0;
        }
        printf("Unloading clawd kernel module...\n");
        int rc = system("sudo rmmod clawd");
        return rc == 0 ? 0 : 1;
    }

    fprintf(stderr, "clawd: unknown kernel command '%s'\n", subcmd);
    fprintf(stderr, "Usage: clawd kernel <status|stats|load|unload>\n");
    return 1;
}

/* ---- Subcommand: version ------------------------------------------------ */

static int cmd_version(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("clawd %s\n", CLAWD_VERSION_STRING);
    printf("Build date: %s\n", CLAWD_BUILD_DATE);
    printf("Commit:     %s\n", CLAWD_BUILD_COMMIT);
    printf("Platform:   "
#ifdef __linux__
           "Linux"
#elif defined(__APPLE__)
           "macOS"
#elif defined(__FreeBSD__)
           "FreeBSD"
#else
           "unknown"
#endif
           "\n");
    printf("Compiler:   "
#ifdef __clang__
           "clang %d.%d.%d",
           __clang_major__, __clang_minor__, __clang_patchlevel__
#elif defined(__GNUC__)
           "gcc %d.%d.%d",
           __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__
#else
           "unknown"
#endif
           );
    printf("\n");
    return 0;
}

/* ---- Subcommand: help --------------------------------------------------- */

static int cmd_help(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf(
        "Usage: clawd [options] <command> [args...]\n"
        "\n"
        "Commands:\n"
        "  chat                       Start interactive chat session\n"
        "  ask <question>             Ask a single question\n"
        "  gateway <run|status|stop>  Gateway server management\n"
        "  config <show|set|get|edit> Configuration management\n"
        "  daemon <cmd>               Daemon management (install, start, stop, etc.)\n"
        "  kernel <cmd>               Kernel module management (status, stats, load, unload)\n"
        "  version                    Show version information\n"
        "  help                       Show this help\n"
        "\n"
        "Global options:\n"
        "  -c, --config <path>   Configuration file path\n"
        "  -p, --profile <name>  Configuration profile\n"
        "  -v, --verbose         Increase verbosity (can be repeated)\n"
        "  -q, --quiet           Quiet mode (suppress informational output)\n"
        "      --no-color        Disable color output\n"
        "  -h, --help            Show this help\n"
        "  -V, --version         Show version\n"
        "\n"
        "Environment variables:\n"
        "  CLAWD_CONFIG_DIR   Override config directory\n"
        "  CLAWD_API_KEY      Set API key\n"
        "  CLAWD_MODEL        Set default model\n"
        "  CLAWD_PROVIDER     Set default provider\n"
        "  CLAWD_HOST         Set gateway host\n"
        "  CLAWD_PORT         Set gateway port\n"
        "  CLAWD_SOCKET       Set gateway socket path\n"
        "  CLAWD_LOG_LEVEL    Set log level (0-5 or name)\n"
        "\n"
        "Chat commands (in interactive mode):\n"
        "  /quit, /exit   Exit the chat session\n"
        "  /clear          Clear the screen\n"
        "  /help           Show chat help\n"
        "\n"
        "Examples:\n"
        "  clawd chat                        Start interactive chat\n"
        "  clawd ask \"What is Linux?\"        Ask a single question\n"
        "  clawd gateway run                 Start gateway in foreground\n"
        "  clawd config show                 Show current configuration\n"
        "  clawd config set model.default_model claude-sonnet-4-20250514\n"
        "  clawd daemon install              Install systemd service\n"
        "\n"
    );
    return 0;
}

/* ---- Main --------------------------------------------------------------- */

int main(int argc, char **argv)
{
    /* Long options. */
    enum { OPT_NO_COLOR = 256 };

    static struct option long_options[] = {
        {"config",   required_argument, NULL, 'c'},
        {"profile",  required_argument, NULL, 'p'},
        {"verbose",  no_argument,       NULL, 'v'},
        {"quiet",    no_argument,       NULL, 'q'},
        {"no-color", no_argument,       NULL, OPT_NO_COLOR},
        {"help",     no_argument,       NULL, 'h'},
        {"version",  no_argument,       NULL, 'V'},
        {NULL,       0,                 NULL,  0 }
    };

    /* Parse global options. */
    int opt;
    while ((opt = getopt_long(argc, argv, "+c:p:vqhV", long_options, NULL)) != -1) {
        switch (opt) {
        case 'c':
            g_config_path = optarg;
            break;
        case 'p':
            g_profile = optarg;
            break;
        case 'v':
            g_verbose++;
            break;
        case 'q':
            g_quiet = true;
            break;
        case OPT_NO_COLOR:
            g_color = false;
            break;
        case 'h':
            return cmd_help(0, NULL);
        case 'V':
            return cmd_version(0, NULL);
        default:
            fprintf(stderr, "Try 'clawd --help' for more information.\n");
            return 1;
        }
    }

    /* Disable color if not a TTY or NO_COLOR env is set. */
    if (!isatty(STDOUT_FILENO) || getenv("NO_COLOR"))
        g_color = false;

    /* Load configuration. */
    int rc;
    if (g_config_path) {
        rc = clawd_config_load(g_config_path, &g_cfg);
    } else {
        rc = clawd_config_load_default(&g_cfg);
    }
    if (rc != 0 && !g_quiet) {
        fprintf(stderr, "clawd: warning: failed to load configuration\n");
    }

    /* Apply profile override. */
    if (g_profile) {
        free(g_cfg.profile);
        g_cfg.profile = strdup(g_profile);
    }

    /* Merge environment variables. */
    clawd_config_merge_env(&g_cfg);

    /* Initialize logging. */
    int log_level = CLAWD_LOG_WARN;
    if (g_verbose >= 2)
        log_level = CLAWD_LOG_TRACE;
    else if (g_verbose == 1)
        log_level = CLAWD_LOG_DEBUG;
    else if (g_quiet)
        log_level = CLAWD_LOG_ERROR;

    clawd_log_init("clawd", log_level);

    /* Determine subcommand. */
    if (optind >= argc) {
        /* No subcommand: default to help. */
        int ret = cmd_help(0, NULL);
        clawd_config_free(&g_cfg);
        return ret;
    }

    const char *command = argv[optind];
    int sub_argc = argc - optind - 1;
    char **sub_argv = argv + optind + 1;

    int ret = 0;

    if (strcmp(command, "chat") == 0) {
        ret = cmd_chat(sub_argc, sub_argv);
    } else if (strcmp(command, "ask") == 0) {
        ret = cmd_ask(sub_argc, sub_argv);
    } else if (strcmp(command, "gateway") == 0) {
        ret = cmd_gateway(sub_argc, sub_argv);
    } else if (strcmp(command, "config") == 0) {
        ret = cmd_config(sub_argc, sub_argv);
    } else if (strcmp(command, "daemon") == 0) {
        ret = cmd_daemon(sub_argc, sub_argv);
    } else if (strcmp(command, "kernel") == 0) {
        ret = cmd_kernel(sub_argc, sub_argv);
    } else if (strcmp(command, "version") == 0) {
        ret = cmd_version(sub_argc, sub_argv);
    } else if (strcmp(command, "help") == 0) {
        ret = cmd_help(sub_argc, sub_argv);
    } else {
        fprintf(stderr, "clawd: unknown command '%s'\n", command);
        fprintf(stderr, "Try 'clawd --help' for more information.\n");
        ret = 1;
    }

    clawd_config_free(&g_cfg);
    return ret;
}
