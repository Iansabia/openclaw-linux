/*
 * kelp-tui — Kelp OS Terminal Interface
 *
 * Split-pane TUI: chat on left, live system metrics on right.
 * Streaming responses, modern color palette, status bar.
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/kelp.h>
#include <kelp/config.h>
#include <kelp/paths.h>
#include <kelp/ansi.h>

#include <cjson/cJSON.h>

#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/utsname.h>

#include <ncurses.h>

/* ---- Constants ---------------------------------------------------------- */

#define KELP_TUI_VERSION "1.0.0"

#define INPUT_HEIGHT       3
#define STATUS_HEIGHT      1
#define HEADER_HEIGHT      3
#define MAX_INPUT_LEN      4096
#define MAX_MESSAGES       2048
#define METRICS_WIDTH      32
#define METRICS_REFRESH_MS 1000

/* ---- Color pairs -------------------------------------------------------- */

enum {
    CP_DEFAULT = 0,
    CP_USER,
    CP_ASSISTANT,
    CP_SYSTEM_MSG,
    CP_ERROR,
    CP_CODE,
    CP_STATUS_BAR,
    CP_INPUT_BORDER,
    CP_HIGHLIGHT,
    CP_HEADER,
    CP_HEADER_ACCENT,
    CP_METRICS_TITLE,
    CP_METRICS_LABEL,
    CP_METRICS_VALUE,
    CP_METRICS_GOOD,
    CP_METRICS_BORDER,
    CP_DIM,
    CP_THINKING,
    CP_SEPARATOR,
    CP_INPUT_PROMPT
};

/* ---- Message types ------------------------------------------------------ */

typedef enum {
    MSG_USER,
    MSG_ASSISTANT,
    MSG_SYSTEM,
    MSG_ERROR
} msg_type_t;

typedef struct {
    msg_type_t  type;
    char       *text;
    time_t      timestamp;
} chat_message_t;

/* ---- Kernel metrics ----------------------------------------------------- */

typedef struct {
    /* /proc/kelp/stats */
    long messages_processed;
    long bytes_read;
    long bytes_written;
    int  active_sessions;
    long uptime_sec;

    /* /proc/kelp/scheduler */
    int  queue_depth;
    long total_submitted;
    long total_completed;

    /* /proc/kelp/accelerators */
    int  accel_count;

    /* System */
    long mem_total_kb;
    long mem_free_kb;
    double load_avg;
    char kernel_version[64];

    bool available;
} kelp_metrics_t;

/* ---- TUI state ---------------------------------------------------------- */

typedef struct {
    kelp_config_t cfg;

    /* ncurses windows. */
    WINDOW *win_header;
    WINDOW *win_chat;
    WINDOW *win_metrics;
    WINDOW *win_input;
    WINDOW *win_status;

    int term_rows;
    int term_cols;
    bool wide_mode;      /* true if terminal wide enough for metrics pane */

    /* Chat history. */
    chat_message_t messages[MAX_MESSAGES];
    int             msg_count;
    int             scroll_offset;

    /* Wrapped display lines. */
    char **display_lines;
    int   *display_colors;
    int    display_count;
    int    display_cap;

    /* Input buffer. */
    char   input_buf[MAX_INPUT_LEN];
    int    input_len;
    int    input_pos;

    /* Gateway connection. */
    int    gateway_fd;
    bool   connected;

    /* Status. */
    char   status_model[128];
    int    total_tokens;

    /* Metrics. */
    kelp_metrics_t metrics;
    time_t         metrics_last_update;

    /* Control. */
    bool   running;
    bool   needs_redraw;

    /* Async response. */
    bool              waiting;
    int               think_frame;
    char             *pending_response;
    bool              response_ready;
    bool              response_error;
    pthread_mutex_t   async_lock;

    /* Streaming text reveal. */
    char             *stream_text;
    int               stream_pos;
    int               stream_msg_idx;

    /* Boot time tracking. */
    time_t            start_time;
} tui_state_t;

static tui_state_t g_tui;

/* ---- Forward declarations ----------------------------------------------- */

static void tui_init(void);
static void tui_destroy(void);
static void tui_resize(void);
static void tui_render(void);
static void tui_handle_key(int ch);
static void tui_add_message(msg_type_t type, const char *text);
static void tui_send_message(void);
static int  tui_connect_gateway(void);
static void tui_rebuild_display_lines(void);
static void tui_update_metrics(void);

/* ---- Metrics collection ------------------------------------------------- */

static void read_proc_file(const char *path, char *buf, size_t bufsz)
{
    buf[0] = '\0';
    FILE *f = fopen(path, "r");
    if (!f) return;
    size_t n = fread(buf, 1, bufsz - 1, f);
    buf[n] = '\0';
    fclose(f);
}

static long parse_proc_value(const char *buf, const char *key)
{
    const char *p = strstr(buf, key);
    if (!p) return 0;
    p += strlen(key);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    return strtol(p, NULL, 10);
}

static void tui_update_metrics(void)
{
    time_t now = time(NULL);
    if (now - g_tui.metrics_last_update < 1)
        return;
    g_tui.metrics_last_update = now;

    kelp_metrics_t *m = &g_tui.metrics;
    char buf[2048];

    /* Kernel module stats. */
    read_proc_file("/proc/kelp/stats", buf, sizeof(buf));
    if (buf[0]) {
        m->available = true;
        m->messages_processed = parse_proc_value(buf, "messages_processed");
        m->bytes_read = parse_proc_value(buf, "bytes_read");
        m->bytes_written = parse_proc_value(buf, "bytes_written");
        m->active_sessions = (int)parse_proc_value(buf, "active_sessions");
        m->uptime_sec = parse_proc_value(buf, "uptime_seconds");
    }

    /* Scheduler stats. */
    read_proc_file("/proc/kelp/scheduler", buf, sizeof(buf));
    if (buf[0]) {
        m->queue_depth = (int)parse_proc_value(buf, "queue_depth");
        m->total_submitted = parse_proc_value(buf, "total_submitted");
        m->total_completed = parse_proc_value(buf, "total_completed");
    }

    /* Accelerator stats. */
    read_proc_file("/proc/kelp/accelerators", buf, sizeof(buf));
    m->accel_count = (int)parse_proc_value(buf, "count");

    /* System memory. */
    read_proc_file("/proc/meminfo", buf, sizeof(buf));
    if (buf[0]) {
        m->mem_total_kb = parse_proc_value(buf, "MemTotal");
        m->mem_free_kb = parse_proc_value(buf, "MemAvailable");
        if (m->mem_free_kb == 0)
            m->mem_free_kb = parse_proc_value(buf, "MemFree");
    }

    /* Load average. */
    read_proc_file("/proc/loadavg", buf, sizeof(buf));
    if (buf[0])
        m->load_avg = strtod(buf, NULL);

    /* Kernel version (once). */
    if (!m->kernel_version[0]) {
        struct utsname uts;
        if (uname(&uts) == 0)
            snprintf(m->kernel_version, sizeof(m->kernel_version),
                     "%s", uts.release);
    }
}

/* ---- Gateway communication ---------------------------------------------- */

static int tui_connect_gateway(void)
{
    const char *sock_path = g_tui.cfg.gateway.socket_path;
    char *default_sock = NULL;

    if (!sock_path) {
        default_sock = kelp_paths_socket();
        sock_path = default_sock;
    }
    if (!sock_path) {
        tui_add_message(MSG_ERROR, "Cannot determine gateway socket path.");
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        tui_add_message(MSG_ERROR, "Failed to create socket.");
        free(default_sock);
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        free(default_sock);
        /* Silent on boot — don't spam errors */
        g_tui.connected = false;
        return -1;
    }

    free(default_sock);
    g_tui.gateway_fd = fd;
    g_tui.connected = true;
    return 0;
}

static char *gateway_rpc_call(const char *method, cJSON *params)
{
    const char *sock_path = g_tui.cfg.gateway.socket_path;
    char *default_sock = NULL;
    if (!sock_path) {
        default_sock = kelp_paths_socket();
        sock_path = default_sock;
    }
    if (!sock_path) {
        free(default_sock);
        g_tui.connected = false;
        return NULL;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { free(default_sock); g_tui.connected = false; return NULL; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);
    free(default_sock);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        g_tui.connected = false;
        return NULL;
    }
    g_tui.connected = true;

    static int rpc_id = 1;
    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "jsonrpc", "2.0");
    cJSON_AddNumberToObject(req, "id", rpc_id++);
    cJSON_AddStringToObject(req, "method", method);
    if (params)
        cJSON_AddItemToObject(req, "params", cJSON_Duplicate(params, 1));

    char *payload = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);
    if (!payload) { close(fd); return NULL; }

    size_t plen = strlen(payload);
    char *sendbuf = malloc(plen + 2);
    if (!sendbuf) { free(payload); close(fd); return NULL; }
    memcpy(sendbuf, payload, plen);
    sendbuf[plen] = '\n';
    sendbuf[plen + 1] = '\0';
    free(payload);

    ssize_t sent = 0, total = (ssize_t)(plen + 1);
    while (sent < total) {
        ssize_t n = write(fd, sendbuf + sent, (size_t)(total - sent));
        if (n <= 0) { free(sendbuf); close(fd); g_tui.connected = false; return NULL; }
        sent += n;
    }
    free(sendbuf);

    kelp_str_t resp = kelp_str_new();
    char buf[4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n <= 0) break;
        buf[n] = '\0';
        kelp_str_append(&resp, buf, (size_t)n);
        if (resp.len > 0 && resp.data[resp.len - 1] == '\n') break;
    }
    close(fd);

    if (resp.len == 0) { kelp_str_free(&resp); g_tui.connected = false; return NULL; }
    kelp_str_trim(&resp);
    char *result = resp.data;
    resp.data = NULL;
    return result;
}

/* ---- Async response thread ---------------------------------------------- */

static void *response_thread_fn(void *arg)
{
    char *msg_text = (char *)arg;
    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "message", msg_text);
    cJSON_AddStringToObject(params, "channel_id", "tui");
    cJSON_AddStringToObject(params, "user_id", "local");

    char *resp_str = gateway_rpc_call("chat.send", params);
    cJSON_Delete(params);
    free(msg_text);

    pthread_mutex_lock(&g_tui.async_lock);
    if (!resp_str) {
        g_tui.pending_response = strdup("No response from gateway.");
        g_tui.response_error = true;
    } else {
        cJSON *resp = kelp_json_parse(resp_str);
        free(resp_str);
        if (!resp) {
            g_tui.pending_response = strdup("Failed to parse response.");
            g_tui.response_error = true;
        } else {
            cJSON *error = cJSON_GetObjectItem(resp, "error");
            if (error) {
                const char *errmsg = kelp_json_get_string(error, "message");
                char errbuf[512];
                snprintf(errbuf, sizeof(errbuf), "%s", errmsg ? errmsg : "unknown error");
                g_tui.pending_response = strdup(errbuf);
                g_tui.response_error = true;
            } else {
                cJSON *result_obj = cJSON_GetObjectItem(resp, "result");
                const char *content = result_obj
                    ? kelp_json_get_string(result_obj, "content") : NULL;
                g_tui.pending_response = strdup(content ? content : "(empty)");
                g_tui.response_error = false;
            }
            cJSON_Delete(resp);
        }
    }
    g_tui.response_ready = true;
    pthread_mutex_unlock(&g_tui.async_lock);
    return NULL;
}

static void tui_send_message(void)
{
    if (g_tui.input_len == 0 || g_tui.waiting) return;

    g_tui.input_buf[g_tui.input_len] = '\0';
    char *msg_text = strdup(g_tui.input_buf);
    if (!msg_text) return;

    g_tui.input_len = 0;
    g_tui.input_pos = 0;
    g_tui.input_buf[0] = '\0';

    /* Commands. */
    if (strcmp(msg_text, "/quit") == 0 || strcmp(msg_text, "/exit") == 0) {
        g_tui.running = false;
        free(msg_text);
        return;
    }
    if (strcmp(msg_text, "/clear") == 0) {
        g_tui.msg_count = 0;
        g_tui.scroll_offset = 0;
        g_tui.needs_redraw = true;
        free(msg_text);
        return;
    }

    tui_add_message(MSG_USER, msg_text);
    g_tui.needs_redraw = true;
    tui_render();
    doupdate();

    g_tui.waiting = true;
    g_tui.think_frame = 0;
    g_tui.response_ready = false;
    g_tui.response_error = false;

    pthread_t tid;
    if (pthread_create(&tid, NULL, response_thread_fn, msg_text) == 0)
        pthread_detach(tid);
    else {
        tui_add_message(MSG_ERROR, "Failed to start response thread.");
        g_tui.waiting = false;
        free(msg_text);
    }
    g_tui.needs_redraw = true;
}

/* ---- Message management ------------------------------------------------- */

static void tui_add_message(msg_type_t type, const char *text)
{
    if (g_tui.msg_count >= MAX_MESSAGES) {
        free(g_tui.messages[0].text);
        memmove(&g_tui.messages[0], &g_tui.messages[1],
                sizeof(chat_message_t) * (MAX_MESSAGES - 1));
        g_tui.msg_count = MAX_MESSAGES - 1;
    }
    chat_message_t *msg = &g_tui.messages[g_tui.msg_count];
    msg->type = type;
    msg->text = strdup(text);
    msg->timestamp = time(NULL);
    g_tui.msg_count++;
    g_tui.scroll_offset = 0;
}

/* ---- Display line wrapping ---------------------------------------------- */

static void tui_display_lines_clear(void)
{
    if (g_tui.display_lines) {
        for (int i = 0; i < g_tui.display_count; i++)
            free(g_tui.display_lines[i]);
        free(g_tui.display_lines);
        g_tui.display_lines = NULL;
    }
    free(g_tui.display_colors);
    g_tui.display_colors = NULL;
    g_tui.display_count = 0;
    g_tui.display_cap = 0;
}

static void dl_add(const char *line, int cp)
{
    if (g_tui.display_count >= g_tui.display_cap) {
        int nc = g_tui.display_cap == 0 ? 256 : g_tui.display_cap * 2;
        g_tui.display_lines  = realloc(g_tui.display_lines,  sizeof(char *) * (size_t)nc);
        g_tui.display_colors = realloc(g_tui.display_colors, sizeof(int) * (size_t)nc);
        g_tui.display_cap = nc;
    }
    g_tui.display_lines[g_tui.display_count]  = strdup(line);
    g_tui.display_colors[g_tui.display_count] = cp;
    g_tui.display_count++;
}

static void tui_rebuild_display_lines(void)
{
    tui_display_lines_clear();

    int chat_w = g_tui.wide_mode
        ? g_tui.term_cols - METRICS_WIDTH - 3
        : g_tui.term_cols - 2;
    if (chat_w < 20) chat_w = 20;

    for (int i = 0; i < g_tui.msg_count; i++) {
        chat_message_t *msg = &g_tui.messages[i];
        int cp;
        const char *prefix;

        switch (msg->type) {
        case MSG_USER:      cp = CP_USER;       prefix = "  > "; break;
        case MSG_ASSISTANT: cp = CP_ASSISTANT;   prefix = "  "; break;
        case MSG_SYSTEM:    cp = CP_SYSTEM_MSG;  prefix = "  "; break;
        case MSG_ERROR:     cp = CP_ERROR;       prefix = "  "; break;
        default:            cp = CP_DEFAULT;     prefix = "  "; break;
        }

        /* Label line. */
        if (msg->type == MSG_USER) {
            dl_add("  you", CP_DIM);
        } else if (msg->type == MSG_ASSISTANT) {
            dl_add("  kelp", CP_HEADER_ACCENT);
        }

        kelp_str_t full = kelp_str_new();
        kelp_str_append_cstr(&full, prefix);
        kelp_str_append_cstr(&full, msg->text);

        const char *p = full.data;
        int remaining = (int)full.len;

        while (remaining > 0) {
            int ll = remaining > chat_w ? chat_w : remaining;
            if (ll < remaining) {
                int brk = ll;
                while (brk > 0 && p[brk] != ' ' && p[brk] != '\n') brk--;
                if (brk > 0) ll = brk + 1;
            }
            for (int j = 0; j < ll; j++) {
                if (p[j] == '\n') { ll = j + 1; break; }
            }
            int cl = ll;
            while (cl > 0 && (p[cl-1] == '\n' || p[cl-1] == '\r')) cl--;

            char tmp[4096];
            if (cl >= (int)sizeof(tmp)) cl = (int)sizeof(tmp) - 1;
            memcpy(tmp, p, (size_t)cl);
            tmp[cl] = '\0';

            /* Detect code blocks (lines starting with spaces after prefix or ```) */
            bool is_code = (strncmp(tmp + strlen(prefix), "```", 3) == 0) ||
                           (strlen(tmp) > strlen(prefix) + 4 &&
                            tmp[strlen(prefix)] == ' ' && tmp[strlen(prefix)+1] == ' ' &&
                            tmp[strlen(prefix)+2] == ' ' && tmp[strlen(prefix)+3] == ' ');
            dl_add(tmp, is_code ? CP_CODE : cp);

            p += ll;
            remaining -= ll;
        }
        kelp_str_free(&full);
        dl_add("", CP_DEFAULT);
    }
}

/* ---- TUI initialization ------------------------------------------------- */

static void init_colors(void)
{
    start_color();
    use_default_colors();

    /* Modern palette — dark background assumed. */
    if (can_change_color() && COLORS >= 256) {
        /* Use 256-color palette for richer colors. */
        init_pair(CP_USER,          COLOR_GREEN,    -1);
        init_pair(CP_ASSISTANT,     COLOR_WHITE,    -1);
        init_pair(CP_SYSTEM_MSG,    COLOR_YELLOW,   -1);
        init_pair(CP_ERROR,         COLOR_RED,      -1);
        init_pair(CP_CODE,          COLOR_CYAN,     -1);
        init_pair(CP_STATUS_BAR,    COLOR_BLACK,    COLOR_GREEN);
        init_pair(CP_INPUT_BORDER,  COLOR_GREEN,    -1);
        init_pair(CP_HIGHLIGHT,     COLOR_BLACK,    COLOR_YELLOW);
        init_pair(CP_HEADER,        COLOR_WHITE,    -1);
        init_pair(CP_HEADER_ACCENT, COLOR_GREEN,    -1);
        init_pair(CP_METRICS_TITLE, COLOR_GREEN,    -1);
        init_pair(CP_METRICS_LABEL, COLOR_WHITE,    -1);
        init_pair(CP_METRICS_VALUE, COLOR_CYAN,     -1);
        init_pair(CP_METRICS_GOOD,  COLOR_GREEN,    -1);
        init_pair(CP_METRICS_BORDER,COLOR_GREEN,    -1);
        init_pair(CP_DIM,           COLOR_WHITE,    -1);
        init_pair(CP_THINKING,      COLOR_YELLOW,   -1);
        init_pair(CP_SEPARATOR,     COLOR_GREEN,    -1);
        init_pair(CP_INPUT_PROMPT,  COLOR_GREEN,    -1);
    } else {
        init_pair(CP_USER,          COLOR_GREEN,    -1);
        init_pair(CP_ASSISTANT,     COLOR_WHITE,    -1);
        init_pair(CP_SYSTEM_MSG,    COLOR_YELLOW,   -1);
        init_pair(CP_ERROR,         COLOR_RED,      -1);
        init_pair(CP_CODE,          COLOR_CYAN,     -1);
        init_pair(CP_STATUS_BAR,    COLOR_BLACK,    COLOR_GREEN);
        init_pair(CP_INPUT_BORDER,  COLOR_GREEN,    -1);
        init_pair(CP_HIGHLIGHT,     COLOR_BLACK,    COLOR_YELLOW);
        init_pair(CP_HEADER,        COLOR_WHITE,    -1);
        init_pair(CP_HEADER_ACCENT, COLOR_GREEN,    -1);
        init_pair(CP_METRICS_TITLE, COLOR_GREEN,    -1);
        init_pair(CP_METRICS_LABEL, COLOR_WHITE,    -1);
        init_pair(CP_METRICS_VALUE, COLOR_CYAN,     -1);
        init_pair(CP_METRICS_GOOD,  COLOR_GREEN,    -1);
        init_pair(CP_METRICS_BORDER,COLOR_GREEN,    -1);
        init_pair(CP_DIM,           COLOR_WHITE,    -1);
        init_pair(CP_THINKING,      COLOR_YELLOW,   -1);
        init_pair(CP_SEPARATOR,     COLOR_GREEN,    -1);
        init_pair(CP_INPUT_PROMPT,  COLOR_GREEN,    -1);
    }
}

static void tui_create_windows(void)
{
    getmaxyx(stdscr, g_tui.term_rows, g_tui.term_cols);
    g_tui.wide_mode = (g_tui.term_cols >= 100);

    int chat_width = g_tui.wide_mode
        ? g_tui.term_cols - METRICS_WIDTH - 1
        : g_tui.term_cols;

    int body_height = g_tui.term_rows - HEADER_HEIGHT - INPUT_HEIGHT - STATUS_HEIGHT;
    if (body_height < 3) body_height = 3;

    g_tui.win_header  = newwin(HEADER_HEIGHT, g_tui.term_cols, 0, 0);
    g_tui.win_chat    = newwin(body_height, chat_width, HEADER_HEIGHT, 0);
    g_tui.win_status  = newwin(STATUS_HEIGHT, g_tui.term_cols,
                               HEADER_HEIGHT + body_height, 0);
    g_tui.win_input   = newwin(INPUT_HEIGHT, g_tui.term_cols,
                               HEADER_HEIGHT + body_height + STATUS_HEIGHT, 0);

    if (g_tui.wide_mode)
        g_tui.win_metrics = newwin(body_height, METRICS_WIDTH,
                                   HEADER_HEIGHT, chat_width + 1);
    else
        g_tui.win_metrics = NULL;

    scrollok(g_tui.win_chat, TRUE);
    keypad(g_tui.win_input, TRUE);
}

static void tui_init(void)
{
    setlocale(LC_ALL, "");
    initscr();
    init_colors();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    timeout(50);
    curs_set(1);

    tui_create_windows();

    g_tui.running       = true;
    g_tui.needs_redraw  = true;
    g_tui.gateway_fd    = -1;
    g_tui.connected     = false;
    g_tui.msg_count     = 0;
    g_tui.scroll_offset = 0;
    g_tui.input_len     = 0;
    g_tui.input_pos     = 0;
    g_tui.input_buf[0]  = '\0';
    g_tui.total_tokens  = 0;
    g_tui.start_time    = time(NULL);
    g_tui.metrics_last_update = 0;

    g_tui.waiting          = false;
    g_tui.response_ready   = false;
    g_tui.pending_response = NULL;
    g_tui.stream_text      = NULL;
    g_tui.stream_pos       = 0;
    pthread_mutex_init(&g_tui.async_lock, NULL);
    snprintf(g_tui.status_model, sizeof(g_tui.status_model), "%s",
             g_tui.cfg.model.default_model ? g_tui.cfg.model.default_model
                                           : "claude-sonnet-4-20250514");

    memset(&g_tui.metrics, 0, sizeof(g_tui.metrics));
}

static void tui_destroy(void)
{
    for (int i = 0; i < g_tui.msg_count; i++)
        free(g_tui.messages[i].text);
    tui_display_lines_clear();
    pthread_mutex_destroy(&g_tui.async_lock);
    free(g_tui.pending_response);
    free(g_tui.stream_text);

    if (g_tui.win_header)  delwin(g_tui.win_header);
    if (g_tui.win_chat)    delwin(g_tui.win_chat);
    if (g_tui.win_metrics) delwin(g_tui.win_metrics);
    if (g_tui.win_input)   delwin(g_tui.win_input);
    if (g_tui.win_status)  delwin(g_tui.win_status);
    endwin();

    if (g_tui.gateway_fd >= 0) close(g_tui.gateway_fd);
}

/* ---- Resize ------------------------------------------------------------- */

static void tui_resize(void)
{
    endwin();
    refresh();

    if (g_tui.win_header)  delwin(g_tui.win_header);
    if (g_tui.win_chat)    delwin(g_tui.win_chat);
    if (g_tui.win_metrics) delwin(g_tui.win_metrics);
    if (g_tui.win_input)   delwin(g_tui.win_input);
    if (g_tui.win_status)  delwin(g_tui.win_status);
    g_tui.win_metrics = NULL;

    tui_create_windows();
    g_tui.needs_redraw = true;
}

/* ---- Rendering ---------------------------------------------------------- */

static void tui_render_header(void)
{
    werase(g_tui.win_header);

    /* Logo line. */
    wattron(g_tui.win_header, COLOR_PAIR(CP_HEADER_ACCENT) | A_BOLD);
    mvwprintw(g_tui.win_header, 0, 2, "KELP OS");
    wattroff(g_tui.win_header, A_BOLD);
    wattron(g_tui.win_header, COLOR_PAIR(CP_DIM));
    wprintw(g_tui.win_header, "  v1.0.0");
    wattroff(g_tui.win_header, COLOR_PAIR(CP_DIM));

    /* Right-aligned info. */
    if (g_tui.metrics.available) {
        char uptime[32];
        long up = g_tui.metrics.uptime_sec;
        if (up > 3600)
            snprintf(uptime, sizeof(uptime), "%ldh%02ldm", up/3600, (up%3600)/60);
        else if (up > 60)
            snprintf(uptime, sizeof(uptime), "%ldm%02lds", up/60, up%60);
        else
            snprintf(uptime, sizeof(uptime), "%lds", up);

        char info[64];
        snprintf(info, sizeof(info), "uptime %s", uptime);
        wattron(g_tui.win_header, COLOR_PAIR(CP_DIM));
        mvwprintw(g_tui.win_header, 0, g_tui.term_cols - (int)strlen(info) - 2, "%s", info);
        wattroff(g_tui.win_header, COLOR_PAIR(CP_DIM));
    }

    /* Separator line. */
    wattron(g_tui.win_header, COLOR_PAIR(CP_SEPARATOR));
    wmove(g_tui.win_header, 2, 0);
    for (int i = 0; i < g_tui.term_cols; i++)
        waddch(g_tui.win_header, ACS_HLINE);
    wattroff(g_tui.win_header, COLOR_PAIR(CP_SEPARATOR));

    wnoutrefresh(g_tui.win_header);
}

static void tui_render_chat(void)
{
    werase(g_tui.win_chat);
    tui_rebuild_display_lines();

    int body_height = g_tui.term_rows - HEADER_HEIGHT - INPUT_HEIGHT - STATUS_HEIGHT;
    if (body_height < 1) body_height = 1;

    int total = g_tui.display_count;
    int start = total - body_height - g_tui.scroll_offset;
    if (start < 0) start = 0;

    int row = 0;
    for (int i = start; i < total && row < body_height; i++, row++) {
        int cp = g_tui.display_colors[i];
        if (cp != CP_DEFAULT)
            wattron(g_tui.win_chat, COLOR_PAIR(cp));
        if (cp == CP_USER)
            wattron(g_tui.win_chat, A_BOLD);
        if (cp == CP_DIM)
            wattron(g_tui.win_chat, A_DIM);
        if (cp == CP_CODE)
            wattron(g_tui.win_chat, A_DIM);

        mvwprintw(g_tui.win_chat, row, 0, "%s", g_tui.display_lines[i]);

        if (cp == CP_CODE)   wattroff(g_tui.win_chat, A_DIM);
        if (cp == CP_DIM)    wattroff(g_tui.win_chat, A_DIM);
        if (cp == CP_USER)   wattroff(g_tui.win_chat, A_BOLD);
        if (cp != CP_DEFAULT) wattroff(g_tui.win_chat, COLOR_PAIR(cp));
    }

    /* Thinking animation at bottom. */
    if (g_tui.waiting && !g_tui.stream_text) {
        const char *frames[] = {
            "  thinking    ",
            "  thinking .  ",
            "  thinking .. ",
            "  thinking ...",
        };
        int fi = (g_tui.think_frame / 6) % 4;
        wattron(g_tui.win_chat, COLOR_PAIR(CP_THINKING) | A_DIM);
        mvwprintw(g_tui.win_chat, body_height - 1, 0, "%s", frames[fi]);
        wattroff(g_tui.win_chat, COLOR_PAIR(CP_THINKING) | A_DIM);
    }

    wnoutrefresh(g_tui.win_chat);
}

static void metrics_line(WINDOW *w, int row, const char *label, const char *value, int vcp)
{
    wattron(w, COLOR_PAIR(CP_METRICS_LABEL) | A_DIM);
    mvwprintw(w, row, 1, "%-16s", label);
    wattroff(w, COLOR_PAIR(CP_METRICS_LABEL) | A_DIM);
    wattron(w, COLOR_PAIR(vcp));
    wprintw(w, "%s", value);
    wattroff(w, COLOR_PAIR(vcp));
}

static void tui_render_metrics(void)
{
    if (!g_tui.win_metrics) return;

    werase(g_tui.win_metrics);
    kelp_metrics_t *m = &g_tui.metrics;

    int body_height = g_tui.term_rows - HEADER_HEIGHT - INPUT_HEIGHT - STATUS_HEIGHT;

    /* Border. */
    wattron(g_tui.win_metrics, COLOR_PAIR(CP_METRICS_BORDER));
    for (int i = 0; i < body_height; i++)
        mvwaddch(g_tui.win_metrics, i, 0, ACS_VLINE);
    wattroff(g_tui.win_metrics, COLOR_PAIR(CP_METRICS_BORDER));

    int row = 1;

    /* Kernel section. */
    wattron(g_tui.win_metrics, COLOR_PAIR(CP_METRICS_TITLE) | A_BOLD);
    mvwprintw(g_tui.win_metrics, row++, 2, "/dev/kelp");
    wattroff(g_tui.win_metrics, COLOR_PAIR(CP_METRICS_TITLE) | A_BOLD);
    row++;

    if (m->available) {
        char val[32];
        snprintf(val, sizeof(val), "%ld", m->messages_processed);
        metrics_line(g_tui.win_metrics, row++, "messages", val, CP_METRICS_VALUE);

        snprintf(val, sizeof(val), "%d", m->active_sessions);
        metrics_line(g_tui.win_metrics, row++, "sessions", val, CP_METRICS_VALUE);
        row++;

        /* Scheduler section. */
        wattron(g_tui.win_metrics, COLOR_PAIR(CP_METRICS_TITLE) | A_BOLD);
        mvwprintw(g_tui.win_metrics, row++, 2, "ai scheduler");
        wattroff(g_tui.win_metrics, COLOR_PAIR(CP_METRICS_TITLE) | A_BOLD);
        row++;

        snprintf(val, sizeof(val), "%d", m->queue_depth);
        metrics_line(g_tui.win_metrics, row++, "queue depth", val,
                     m->queue_depth > 0 ? CP_THINKING : CP_METRICS_GOOD);

        snprintf(val, sizeof(val), "%ld", m->total_submitted);
        metrics_line(g_tui.win_metrics, row++, "submitted", val, CP_METRICS_VALUE);

        snprintf(val, sizeof(val), "%ld", m->total_completed);
        metrics_line(g_tui.win_metrics, row++, "completed", val, CP_METRICS_GOOD);
    } else {
        wattron(g_tui.win_metrics, COLOR_PAIR(CP_DIM) | A_DIM);
        mvwprintw(g_tui.win_metrics, row++, 2, "module not loaded");
        wattroff(g_tui.win_metrics, COLOR_PAIR(CP_DIM) | A_DIM);
    }

    row += 2;

    /* System section. */
    wattron(g_tui.win_metrics, COLOR_PAIR(CP_METRICS_TITLE) | A_BOLD);
    mvwprintw(g_tui.win_metrics, row++, 2, "system");
    wattroff(g_tui.win_metrics, COLOR_PAIR(CP_METRICS_TITLE) | A_BOLD);
    row++;

    if (m->mem_total_kb > 0) {
        char val[32];
        long used = m->mem_total_kb - m->mem_free_kb;
        snprintf(val, sizeof(val), "%ldM / %ldM",
                 used / 1024, m->mem_total_kb / 1024);
        metrics_line(g_tui.win_metrics, row++, "memory", val, CP_METRICS_VALUE);
    }

    {
        char val[32];
        snprintf(val, sizeof(val), "%.2f", m->load_avg);
        metrics_line(g_tui.win_metrics, row++, "load", val, CP_METRICS_VALUE);
    }

    if (m->kernel_version[0]) {
        /* Truncate kernel version to fit. */
        char kv[20];
        snprintf(kv, sizeof(kv), "%s", m->kernel_version);
        metrics_line(g_tui.win_metrics, row++, "kernel", kv, CP_DIM);
    }

    wnoutrefresh(g_tui.win_metrics);
}

static void tui_render_status(void)
{
    werase(g_tui.win_status);
    wattron(g_tui.win_status, COLOR_PAIR(CP_STATUS_BAR));
    for (int i = 0; i < g_tui.term_cols; i++)
        mvwaddch(g_tui.win_status, 0, i, ' ');

    /* Left: connection. */
    if (g_tui.connected) {
        wattron(g_tui.win_status, A_BOLD);
        mvwprintw(g_tui.win_status, 0, 1, " CONNECTED ");
        wattroff(g_tui.win_status, A_BOLD);
    } else {
        mvwprintw(g_tui.win_status, 0, 1, " OFFLINE ");
    }

    /* Center: model. */
    int ml = (int)strlen(g_tui.status_model);
    int cp = (g_tui.term_cols - ml) / 2;
    if (cp < 15) cp = 15;
    mvwprintw(g_tui.win_status, 0, cp, "%s", g_tui.status_model);

    /* Right: message count. */
    char ri[32];
    snprintf(ri, sizeof(ri), "%d msgs ", g_tui.msg_count);
    mvwprintw(g_tui.win_status, 0, g_tui.term_cols - (int)strlen(ri) - 1, "%s", ri);

    wattroff(g_tui.win_status, COLOR_PAIR(CP_STATUS_BAR));
    wnoutrefresh(g_tui.win_status);
}

static void tui_render_input(void)
{
    werase(g_tui.win_input);

    /* Border. */
    wattron(g_tui.win_input, COLOR_PAIR(CP_INPUT_BORDER));
    box(g_tui.win_input, 0, 0);
    wattroff(g_tui.win_input, COLOR_PAIR(CP_INPUT_BORDER));

    /* Prompt. */
    wattron(g_tui.win_input, COLOR_PAIR(CP_INPUT_PROMPT) | A_BOLD);
    mvwprintw(g_tui.win_input, 1, 2, ">");
    wattroff(g_tui.win_input, COLOR_PAIR(CP_INPUT_PROMPT) | A_BOLD);

    /* Input text. */
    int iw = g_tui.term_cols - 6;
    if (iw < 1) iw = 1;
    int vs = 0;
    if (g_tui.input_pos > iw) vs = g_tui.input_pos - iw;

    for (int i = 0; i < iw && (vs + i) < g_tui.input_len; i++)
        mvwaddch(g_tui.win_input, 1, 4 + i,
                 (chtype)(unsigned char)g_tui.input_buf[vs + i]);

    int cx = 4 + (g_tui.input_pos - vs);
    if (cx >= g_tui.term_cols - 1) cx = g_tui.term_cols - 2;
    wmove(g_tui.win_input, 1, cx);

    wnoutrefresh(g_tui.win_input);
}

static void tui_render(void)
{
    tui_render_header();
    tui_render_chat();
    tui_render_metrics();
    tui_render_status();
    tui_render_input();
    doupdate();
    g_tui.needs_redraw = false;
}

/* ---- Key handling ------------------------------------------------------- */

static void tui_handle_key(int ch)
{
    switch (ch) {
    case ERR: break;
    case KEY_RESIZE: tui_resize(); break;
    case 3: g_tui.running = false; break;         /* Ctrl-C */
    case 12:                                       /* Ctrl-L */
        clearok(curscr, TRUE);
        g_tui.needs_redraw = true;
        break;
    case '\n': case '\r': case KEY_ENTER:
        tui_send_message();
        break;
    case KEY_BACKSPACE: case 127: case 8:
        if (g_tui.input_pos > 0) {
            memmove(&g_tui.input_buf[g_tui.input_pos - 1],
                    &g_tui.input_buf[g_tui.input_pos],
                    (size_t)(g_tui.input_len - g_tui.input_pos));
            g_tui.input_pos--;
            g_tui.input_len--;
            g_tui.input_buf[g_tui.input_len] = '\0';
            g_tui.needs_redraw = true;
        }
        break;
    case KEY_DC:
        if (g_tui.input_pos < g_tui.input_len) {
            memmove(&g_tui.input_buf[g_tui.input_pos],
                    &g_tui.input_buf[g_tui.input_pos + 1],
                    (size_t)(g_tui.input_len - g_tui.input_pos - 1));
            g_tui.input_len--;
            g_tui.input_buf[g_tui.input_len] = '\0';
            g_tui.needs_redraw = true;
        }
        break;
    case KEY_LEFT:
        if (g_tui.input_pos > 0) { g_tui.input_pos--; g_tui.needs_redraw = true; }
        break;
    case KEY_RIGHT:
        if (g_tui.input_pos < g_tui.input_len) { g_tui.input_pos++; g_tui.needs_redraw = true; }
        break;
    case KEY_HOME: case 1:
        g_tui.input_pos = 0; g_tui.needs_redraw = true;
        break;
    case KEY_END: case 5:
        g_tui.input_pos = g_tui.input_len; g_tui.needs_redraw = true;
        break;
    case 21: /* Ctrl-U */
        g_tui.input_len = 0; g_tui.input_pos = 0;
        g_tui.input_buf[0] = '\0'; g_tui.needs_redraw = true;
        break;
    case 23: { /* Ctrl-W */
        if (g_tui.input_pos > 0) {
            int end = g_tui.input_pos;
            while (g_tui.input_pos > 0 && g_tui.input_buf[g_tui.input_pos-1] == ' ')
                g_tui.input_pos--;
            while (g_tui.input_pos > 0 && g_tui.input_buf[g_tui.input_pos-1] != ' ')
                g_tui.input_pos--;
            int del = end - g_tui.input_pos;
            memmove(&g_tui.input_buf[g_tui.input_pos], &g_tui.input_buf[end],
                    (size_t)(g_tui.input_len - end));
            g_tui.input_len -= del;
            g_tui.input_buf[g_tui.input_len] = '\0';
            g_tui.needs_redraw = true;
        }
        break;
    }
    case KEY_PPAGE: {
        int bh = g_tui.term_rows - HEADER_HEIGHT - INPUT_HEIGHT - STATUS_HEIGHT;
        g_tui.scroll_offset += bh / 2;
        int mx = g_tui.display_count - bh;
        if (mx < 0) mx = 0;
        if (g_tui.scroll_offset > mx) g_tui.scroll_offset = mx;
        g_tui.needs_redraw = true;
        break;
    }
    case KEY_NPAGE: {
        int bh = g_tui.term_rows - HEADER_HEIGHT - INPUT_HEIGHT - STATUS_HEIGHT;
        g_tui.scroll_offset -= bh / 2;
        if (g_tui.scroll_offset < 0) g_tui.scroll_offset = 0;
        g_tui.needs_redraw = true;
        break;
    }
    default:
        if (ch >= 32 && ch < 127 && g_tui.input_len < MAX_INPUT_LEN - 1) {
            memmove(&g_tui.input_buf[g_tui.input_pos + 1],
                    &g_tui.input_buf[g_tui.input_pos],
                    (size_t)(g_tui.input_len - g_tui.input_pos));
            g_tui.input_buf[g_tui.input_pos] = (char)ch;
            g_tui.input_pos++;
            g_tui.input_len++;
            g_tui.input_buf[g_tui.input_len] = '\0';
            g_tui.needs_redraw = true;
        }
        break;
    }
}

/* ---- Main --------------------------------------------------------------- */

int main(int argc, char **argv)
{
    const char *config_path = NULL;

    static struct option long_options[] = {
        {"config", required_argument, NULL, 'c'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "c:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'c': config_path = optarg; break;
        case 'h':
            printf("Usage: kelp-tui [options]\n\n"
                   "Options:\n"
                   "  -c, --config <path>   Config file\n"
                   "  -h, --help            Help\n\n"
                   "Keys: Enter=send, Ctrl-C=quit, PgUp/PgDn=scroll\n");
            return 0;
        default:
            return 1;
        }
    }

    memset(&g_tui, 0, sizeof(g_tui));
    if (config_path) {
        if (kelp_config_load(config_path, &g_tui.cfg) != 0) {
            fprintf(stderr, "kelp-tui: failed to load config: %s\n", config_path);
            return 1;
        }
    } else {
        kelp_config_load_default(&g_tui.cfg);
    }
    kelp_config_merge_env(&g_tui.cfg);

    kelp_log_init("kelp-tui", KELP_LOG_WARN);
    if (g_tui.cfg.logging.file) {
        FILE *logfp = fopen(g_tui.cfg.logging.file, "a");
        if (logfp) kelp_log_set_file(logfp);
    }

    tui_init();

    /* Welcome. */
    tui_add_message(MSG_SYSTEM, "Kelp OS ready. Type a message to talk to the AI.");

    /* Connect to gateway (silent if not available yet). */
    if (tui_connect_gateway() == 0)
        tui_add_message(MSG_SYSTEM, "Gateway connected.");

    /* Main loop. */
    while (g_tui.running) {
        /* Async response handling. */
        if (g_tui.waiting) {
            pthread_mutex_lock(&g_tui.async_lock);
            if (g_tui.response_ready) {
                g_tui.waiting = false;
                if (g_tui.pending_response) {
                    if (g_tui.response_error) {
                        tui_add_message(MSG_ERROR, g_tui.pending_response);
                        free(g_tui.pending_response);
                    } else {
                        g_tui.stream_text = g_tui.pending_response;
                        g_tui.stream_pos = 0;
                        tui_add_message(MSG_ASSISTANT, "");
                        g_tui.stream_msg_idx = g_tui.msg_count - 1;
                    }
                    g_tui.pending_response = NULL;
                }
                g_tui.needs_redraw = true;
            } else {
                g_tui.think_frame++;
                g_tui.needs_redraw = true;
            }
            pthread_mutex_unlock(&g_tui.async_lock);
        }

        /* Streaming text reveal. */
        if (g_tui.stream_text) {
            int total_len = (int)strlen(g_tui.stream_text);
            int remaining = total_len - g_tui.stream_pos;
            if (remaining > 0) {
                int advance = 6;
                if (total_len > 2000) advance = 20;
                else if (total_len > 500) advance = 12;
                if (advance > remaining) advance = remaining;
                g_tui.stream_pos += advance;

                chat_message_t *msg = &g_tui.messages[g_tui.stream_msg_idx];
                free(msg->text);
                char *partial = malloc((size_t)g_tui.stream_pos + 1);
                if (partial) {
                    memcpy(partial, g_tui.stream_text, (size_t)g_tui.stream_pos);
                    partial[g_tui.stream_pos] = '\0';
                    msg->text = partial;
                } else {
                    msg->text = strdup(g_tui.stream_text);
                    g_tui.stream_pos = total_len;
                }
                g_tui.needs_redraw = true;
            } else {
                free(g_tui.stream_text);
                g_tui.stream_text = NULL;
                g_tui.needs_redraw = true;
            }
        }

        /* Refresh rate. */
        if (g_tui.stream_text || g_tui.waiting)
            timeout(16);
        else
            timeout(100);

        /* Update metrics periodically. */
        tui_update_metrics();

        if (g_tui.needs_redraw)
            tui_render();

        int ch = getch();
        if (ch != ERR)
            tui_handle_key(ch);

        /* Retry gateway connection if disconnected. */
        if (!g_tui.connected && !g_tui.waiting) {
            static time_t last_retry = 0;
            time_t now = time(NULL);
            if (now - last_retry >= 5) {
                last_retry = now;
                tui_connect_gateway();
            }
        }
    }

    tui_destroy();
    kelp_config_free(&g_tui.cfg);
    return 0;
}
