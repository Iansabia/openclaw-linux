/*
 * clawd-linux :: clawd-tui
 * main.c - ncurses-based TUI for interactive chat
 *
 * Usage: clawd-tui [options]
 * Options:
 *   -c, --config <path>   Config file
 *   -h, --help            Help
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/clawd.h>
#include <clawd/config.h>
#include <clawd/paths.h>
#include <clawd/ansi.h>

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

#include <ncurses.h>

/* ---- Constants ---------------------------------------------------------- */

#define CLAWD_TUI_VERSION "0.1.0"

#define INPUT_HEIGHT       3
#define STATUS_HEIGHT      1
#define MAX_INPUT_LEN      4096
#define MAX_HISTORY_LINES  10000
#define MAX_MESSAGES       2048

/* ---- Color pairs -------------------------------------------------------- */

enum {
    CP_DEFAULT = 0,
    CP_USER,
    CP_ASSISTANT,
    CP_SYSTEM,
    CP_ERROR,
    CP_CODE,
    CP_STATUS_BAR,
    CP_INPUT_BORDER,
    CP_HIGHLIGHT
};

/* ---- Message types ------------------------------------------------------ */

typedef enum {
    MSG_USER,
    MSG_ASSISTANT,
    MSG_SYSTEM,
    MSG_ERROR
} msg_type_t;

/* ---- Chat message ------------------------------------------------------- */

typedef struct {
    msg_type_t  type;
    char       *text;
    time_t      timestamp;
} chat_message_t;

/* ---- TUI state ---------------------------------------------------------- */

typedef struct {
    /* Configuration. */
    clawd_config_t cfg;

    /* ncurses windows. */
    WINDOW *win_chat;        /* Scrollable chat history area. */
    WINDOW *win_input;       /* Input editing area. */
    WINDOW *win_status;      /* Status bar. */

    /* Terminal dimensions. */
    int term_rows;
    int term_cols;

    /* Chat history. */
    chat_message_t messages[MAX_MESSAGES];
    int             msg_count;
    int             scroll_offset;  /* 0 = bottom (most recent). */

    /* Wrapped lines for display (computed on render). */
    char **display_lines;
    int   *display_colors;
    int    display_count;
    int    display_cap;

    /* Input buffer. */
    char   input_buf[MAX_INPUT_LEN];
    int    input_len;
    int    input_pos;       /* Cursor position within input_buf. */

    /* Gateway connection. */
    int    gateway_fd;
    bool   connected;

    /* Status information. */
    char   status_model[128];
    int    total_tokens;

    /* Control flags. */
    bool   running;
    bool   needs_redraw;

    /* Async response handling. */
    bool              waiting;           /* true while waiting for gateway */
    int               think_frame;       /* animation frame counter */
    char             *pending_response;  /* response from background thread */
    bool              response_ready;    /* background thread finished */
    bool              response_error;    /* response was an error */
    pthread_mutex_t   async_lock;

    /* Streaming text reveal. */
    char             *stream_text;       /* full text to reveal gradually */
    int               stream_pos;        /* characters revealed so far */
    int               stream_msg_idx;    /* message index being streamed */
} tui_state_t;

static tui_state_t g_tui;

/* ---- Forward declarations ----------------------------------------------- */

static void tui_init(void);
static void tui_destroy(void);
static void tui_resize(void);
static void tui_render(void);
static void tui_render_chat(void);
static void tui_render_input(void);
static void tui_render_status(void);
static void tui_handle_key(int ch);
static void tui_add_message(msg_type_t type, const char *text);
static void tui_send_message(void);
static int  tui_connect_gateway(void);
static void tui_rebuild_display_lines(void);

/* ---- Gateway communication ---------------------------------------------- */

static int tui_connect_gateway(void)
{
    const char *sock_path = g_tui.cfg.gateway.socket_path;
    char *default_sock = NULL;

    if (!sock_path) {
        default_sock = clawd_paths_socket();
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
        char errbuf[256];
        snprintf(errbuf, sizeof(errbuf),
                 "Cannot connect to gateway at %s: %s",
                 sock_path, strerror(errno));
        tui_add_message(MSG_ERROR, errbuf);
        tui_add_message(MSG_SYSTEM, "Start the gateway with: clawd gateway run");
        close(fd);
        free(default_sock);
        return -1;
    }

    free(default_sock);
    g_tui.gateway_fd = fd;
    g_tui.connected = true;
    tui_add_message(MSG_SYSTEM, "Connected to gateway.");
    return 0;
}

static char *gateway_rpc_call(const char *method, cJSON *params)
{
    /* Create a fresh connection per RPC call (server closes after each). */
    const char *sock_path = g_tui.cfg.gateway.socket_path;
    char *default_sock = NULL;
    if (!sock_path) {
        default_sock = clawd_paths_socket();
        sock_path = default_sock;
    }
    if (!sock_path) {
        free(default_sock);
        g_tui.connected = false;
        return NULL;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        free(default_sock);
        g_tui.connected = false;
        return NULL;
    }

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

    ssize_t total_to_send = (ssize_t)(plen + 1);
    ssize_t sent = 0;
    while (sent < total_to_send) {
        ssize_t n = write(fd, sendbuf + sent,
                          (size_t)(total_to_send - sent));
        if (n <= 0) {
            free(sendbuf);
            close(fd);
            g_tui.connected = false;
            return NULL;
        }
        sent += n;
    }
    free(sendbuf);

    /* Read response (newline-delimited). */
    clawd_str_t resp = clawd_str_new();
    char buf[4096];
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
        g_tui.connected = false;
        return NULL;
    }

    clawd_str_trim(&resp);
    char *result = resp.data;
    resp.data = NULL;
    resp.len  = 0;
    resp.cap  = 0;
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
        cJSON *resp = clawd_json_parse(resp_str);
        free(resp_str);
        if (!resp) {
            g_tui.pending_response = strdup("Failed to parse gateway response.");
            g_tui.response_error = true;
        } else {
            cJSON *error = cJSON_GetObjectItem(resp, "error");
            if (error) {
                const char *errmsg = clawd_json_get_string(error, "message");
                char errbuf[512];
                snprintf(errbuf, sizeof(errbuf), "Gateway error: %s",
                         errmsg ? errmsg : "unknown");
                g_tui.pending_response = strdup(errbuf);
                g_tui.response_error = true;
            } else {
                cJSON *result_obj = cJSON_GetObjectItem(resp, "result");
                const char *content = result_obj
                    ? clawd_json_get_string(result_obj, "content") : NULL;
                g_tui.pending_response = strdup(
                    content ? content : "Empty response.");
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
    if (g_tui.input_len == 0 || g_tui.waiting)
        return;

    /* NUL-terminate the input. */
    g_tui.input_buf[g_tui.input_len] = '\0';
    char *msg_text = strdup(g_tui.input_buf);
    if (!msg_text)
        return;

    /* Clear input. */
    g_tui.input_len = 0;
    g_tui.input_pos = 0;
    g_tui.input_buf[0] = '\0';

    /* Handle special commands. */
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
    if (strcmp(msg_text, "/reconnect") == 0) {
        g_tui.connected = false;
        tui_connect_gateway();
        g_tui.needs_redraw = true;
        free(msg_text);
        return;
    }
    if (strcmp(msg_text, "/help") == 0) {
        tui_add_message(MSG_SYSTEM, "Commands:");
        tui_add_message(MSG_SYSTEM, "  /quit, /exit   - Exit");
        tui_add_message(MSG_SYSTEM, "  /clear         - Clear chat");
        tui_add_message(MSG_SYSTEM, "  /reconnect     - Reconnect to gateway");
        tui_add_message(MSG_SYSTEM, "  /help          - Show this help");
        tui_add_message(MSG_SYSTEM, "Shortcuts:");
        tui_add_message(MSG_SYSTEM, "  Ctrl-C         - Quit");
        tui_add_message(MSG_SYSTEM, "  Ctrl-L         - Redraw screen");
        tui_add_message(MSG_SYSTEM, "  PgUp/PgDn      - Scroll chat history");
        g_tui.needs_redraw = true;
        free(msg_text);
        return;
    }

    /* Add user message to history. */
    tui_add_message(MSG_USER, msg_text);
    g_tui.needs_redraw = true;
    tui_render();
    doupdate();

    /* Launch async request in background thread. */
    g_tui.waiting = true;
    g_tui.think_frame = 0;
    g_tui.response_ready = false;
    g_tui.response_error = false;

    pthread_t tid;
    if (pthread_create(&tid, NULL, response_thread_fn, msg_text) == 0) {
        pthread_detach(tid);
    } else {
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
        /* Shift messages down, discard oldest. */
        free(g_tui.messages[0].text);
        memmove(&g_tui.messages[0], &g_tui.messages[1],
                sizeof(chat_message_t) * (MAX_MESSAGES - 1));
        g_tui.msg_count = MAX_MESSAGES - 1;
    }

    chat_message_t *msg = &g_tui.messages[g_tui.msg_count];
    msg->type      = type;
    msg->text      = strdup(text);
    msg->timestamp = time(NULL);
    g_tui.msg_count++;

    /* Auto-scroll to bottom when new message arrives. */
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
    if (g_tui.display_colors) {
        free(g_tui.display_colors);
        g_tui.display_colors = NULL;
    }
    g_tui.display_count = 0;
    g_tui.display_cap   = 0;
}

static void tui_display_lines_add(const char *line, int color_pair)
{
    if (g_tui.display_count >= g_tui.display_cap) {
        int newcap = g_tui.display_cap == 0 ? 256 : g_tui.display_cap * 2;
        char **new_lines = realloc(g_tui.display_lines,
                                   sizeof(char *) * (size_t)newcap);
        int  *new_colors = realloc(g_tui.display_colors,
                                   sizeof(int) * (size_t)newcap);
        if (!new_lines || !new_colors)
            return;
        g_tui.display_lines  = new_lines;
        g_tui.display_colors = new_colors;
        g_tui.display_cap    = newcap;
    }

    g_tui.display_lines[g_tui.display_count]  = strdup(line);
    g_tui.display_colors[g_tui.display_count] = color_pair;
    g_tui.display_count++;
}

static void tui_rebuild_display_lines(void)
{
    tui_display_lines_clear();

    int chat_width = g_tui.term_cols - 2; /* Account for border. */
    if (chat_width < 10)
        chat_width = 10;

    for (int i = 0; i < g_tui.msg_count; i++) {
        chat_message_t *msg = &g_tui.messages[i];

        /* Determine color pair and prefix. */
        int cp;
        const char *prefix;
        switch (msg->type) {
        case MSG_USER:
            cp = CP_USER;
            prefix = "you> ";
            break;
        case MSG_ASSISTANT:
            cp = CP_ASSISTANT;
            prefix = "assistant> ";
            break;
        case MSG_SYSTEM:
            cp = CP_SYSTEM;
            prefix = "[system] ";
            break;
        case MSG_ERROR:
            cp = CP_ERROR;
            prefix = "[error] ";
            break;
        default:
            cp = CP_DEFAULT;
            prefix = "";
            break;
        }

        /* Build the full line with prefix. */
        clawd_str_t full = clawd_str_new();
        clawd_str_append_cstr(&full, prefix);
        clawd_str_append_cstr(&full, msg->text);

        /* Word-wrap the full line. */
        const char *p = full.data;
        int remaining = (int)full.len;
        bool first_line = true;

        while (remaining > 0) {
            int line_len = remaining > chat_width ? chat_width : remaining;

            /* Try to break at a word boundary. */
            if (line_len < remaining) {
                int brk = line_len;
                while (brk > 0 && p[brk] != ' ' && p[brk] != '\n')
                    brk--;
                if (brk > 0)
                    line_len = brk + 1; /* Include the space. */
            }

            /* Check for embedded newlines. */
            for (int j = 0; j < line_len; j++) {
                if (p[j] == '\n') {
                    line_len = j + 1;
                    break;
                }
            }

            char tmp[4096];
            int copy_len = line_len;
            /* Trim trailing newline/space from display. */
            while (copy_len > 0 && (p[copy_len - 1] == '\n' || p[copy_len - 1] == '\r'))
                copy_len--;

            if (copy_len >= (int)sizeof(tmp))
                copy_len = (int)sizeof(tmp) - 1;
            memcpy(tmp, p, (size_t)copy_len);
            tmp[copy_len] = '\0';

            tui_display_lines_add(tmp, first_line ? cp : cp);
            first_line = false;

            p += line_len;
            remaining -= line_len;
        }

        clawd_str_free(&full);

        /* Add an empty line between messages. */
        tui_display_lines_add("", CP_DEFAULT);
    }
}

/* ---- TUI initialization ------------------------------------------------- */

static void tui_init(void)
{
    /* Set locale for wide character support. */
    setlocale(LC_ALL, "");

    /* Initialize ncurses. */
    initscr();
    start_color();
    use_default_colors();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    nodelay(stdscr, FALSE);
    timeout(100); /* 100ms timeout for getch() to allow periodic tasks. */

    /* Define color pairs. */
    init_pair(CP_USER,         COLOR_GREEN,   -1);
    init_pair(CP_ASSISTANT,    COLOR_WHITE,   -1);
    init_pair(CP_SYSTEM,       COLOR_YELLOW,  -1);
    init_pair(CP_ERROR,        COLOR_RED,     -1);
    init_pair(CP_CODE,         COLOR_CYAN,    -1);
    init_pair(CP_STATUS_BAR,   COLOR_BLACK,   COLOR_WHITE);
    init_pair(CP_INPUT_BORDER, COLOR_BLUE,    -1);
    init_pair(CP_HIGHLIGHT,    COLOR_BLACK,   COLOR_YELLOW);

    /* Hide cursor initially. */
    curs_set(1);

    /* Get terminal dimensions. */
    getmaxyx(stdscr, g_tui.term_rows, g_tui.term_cols);

    /* Create sub-windows. */
    int chat_height = g_tui.term_rows - INPUT_HEIGHT - STATUS_HEIGHT;
    g_tui.win_chat   = newwin(chat_height, g_tui.term_cols, 0, 0);
    g_tui.win_status = newwin(STATUS_HEIGHT, g_tui.term_cols, chat_height, 0);
    g_tui.win_input  = newwin(INPUT_HEIGHT, g_tui.term_cols,
                              chat_height + STATUS_HEIGHT, 0);

    scrollok(g_tui.win_chat, TRUE);
    keypad(g_tui.win_input, TRUE);

    /* Initialize state. */
    g_tui.running      = true;
    g_tui.needs_redraw = true;
    g_tui.gateway_fd   = -1;
    g_tui.connected    = false;
    g_tui.msg_count    = 0;
    g_tui.scroll_offset = 0;
    g_tui.input_len    = 0;
    g_tui.input_pos    = 0;
    g_tui.input_buf[0] = '\0';
    g_tui.total_tokens = 0;

    /* Async state. */
    g_tui.waiting          = false;
    g_tui.response_ready   = false;
    g_tui.pending_response = NULL;
    g_tui.stream_text      = NULL;
    g_tui.stream_pos       = 0;
    pthread_mutex_init(&g_tui.async_lock, NULL);
    snprintf(g_tui.status_model, sizeof(g_tui.status_model), "%s",
             g_tui.cfg.model.default_model ? g_tui.cfg.model.default_model
                                           : "claude-sonnet-4-20250514");

    /* Welcome message. */
    tui_add_message(MSG_SYSTEM,
                    "Welcome to clawd TUI " CLAWD_TUI_VERSION);
    tui_add_message(MSG_SYSTEM,
                    "Type your message and press Enter. "
                    "Type /help for commands.");
}

static void tui_destroy(void)
{
    /* Free messages. */
    for (int i = 0; i < g_tui.msg_count; i++)
        free(g_tui.messages[i].text);

    tui_display_lines_clear();

    /* Clean up async state. */
    pthread_mutex_destroy(&g_tui.async_lock);
    free(g_tui.pending_response);
    free(g_tui.stream_text);

    /* Clean up ncurses. */
    if (g_tui.win_chat)
        delwin(g_tui.win_chat);
    if (g_tui.win_input)
        delwin(g_tui.win_input);
    if (g_tui.win_status)
        delwin(g_tui.win_status);

    endwin();

    /* Close gateway connection. */
    if (g_tui.gateway_fd >= 0) {
        close(g_tui.gateway_fd);
        g_tui.gateway_fd = -1;
    }
}

/* ---- Terminal resize ---------------------------------------------------- */

static void tui_resize(void)
{
    endwin();
    refresh();
    getmaxyx(stdscr, g_tui.term_rows, g_tui.term_cols);

    int chat_height = g_tui.term_rows - INPUT_HEIGHT - STATUS_HEIGHT;
    if (chat_height < 1)
        chat_height = 1;

    /* Resize and reposition windows. */
    wresize(g_tui.win_chat, chat_height, g_tui.term_cols);
    mvwin(g_tui.win_chat, 0, 0);

    wresize(g_tui.win_status, STATUS_HEIGHT, g_tui.term_cols);
    mvwin(g_tui.win_status, chat_height, 0);

    wresize(g_tui.win_input, INPUT_HEIGHT, g_tui.term_cols);
    mvwin(g_tui.win_input, chat_height + STATUS_HEIGHT, 0);

    g_tui.needs_redraw = true;
}

/* ---- Rendering ---------------------------------------------------------- */

static void tui_render_chat(void)
{
    werase(g_tui.win_chat);

    tui_rebuild_display_lines();

    int chat_height = g_tui.term_rows - INPUT_HEIGHT - STATUS_HEIGHT;
    if (chat_height < 1)
        chat_height = 1;

    /* Calculate the starting line based on scroll offset. */
    int total_lines = g_tui.display_count;
    int start_line  = total_lines - chat_height - g_tui.scroll_offset;
    if (start_line < 0)
        start_line = 0;

    int row = 0;
    for (int i = start_line; i < total_lines && row < chat_height; i++, row++) {
        if (g_tui.display_colors[i] != CP_DEFAULT)
            wattron(g_tui.win_chat, COLOR_PAIR(g_tui.display_colors[i]));

        /* Bold for user messages. */
        if (g_tui.display_colors[i] == CP_USER)
            wattron(g_tui.win_chat, A_BOLD);

        mvwprintw(g_tui.win_chat, row, 1, "%s", g_tui.display_lines[i]);

        if (g_tui.display_colors[i] == CP_USER)
            wattroff(g_tui.win_chat, A_BOLD);
        if (g_tui.display_colors[i] != CP_DEFAULT)
            wattroff(g_tui.win_chat, COLOR_PAIR(g_tui.display_colors[i]));
    }

    /* Scroll indicator. */
    if (g_tui.scroll_offset > 0) {
        wattron(g_tui.win_chat, COLOR_PAIR(CP_HIGHLIGHT) | A_BOLD);
        mvwprintw(g_tui.win_chat, 0, g_tui.term_cols - 14, " SCROLLED ^%d ",
                  g_tui.scroll_offset);
        wattroff(g_tui.win_chat, COLOR_PAIR(CP_HIGHLIGHT) | A_BOLD);
    }

    wnoutrefresh(g_tui.win_chat);
}

static void tui_render_status(void)
{
    werase(g_tui.win_status);
    wattron(g_tui.win_status, COLOR_PAIR(CP_STATUS_BAR));

    /* Fill the entire line with spaces for the background. */
    for (int i = 0; i < g_tui.term_cols; i++)
        mvwaddch(g_tui.win_status, 0, i, ' ');

    /* Left side: connection status / thinking animation. */
    if (g_tui.waiting) {
        const char *dots[] = {"   ", ".  ", ".. ", "..."};
        int dot_idx = (g_tui.think_frame / 4) % 4;
        wattron(g_tui.win_status, A_BOLD);
        mvwprintw(g_tui.win_status, 0, 1, " thinking%s ", dots[dot_idx]);
        wattroff(g_tui.win_status, A_BOLD);
    } else if (g_tui.stream_text) {
        wattron(g_tui.win_status, A_BOLD);
        mvwprintw(g_tui.win_status, 0, 1, " streaming... ");
        wattroff(g_tui.win_status, A_BOLD);
    } else if (g_tui.connected) {
        mvwprintw(g_tui.win_status, 0, 1, " [connected] ");
    } else {
        mvwprintw(g_tui.win_status, 0, 1, " [disconnected] ");
    }

    /* Center: model name. */
    int model_len = (int)strlen(g_tui.status_model);
    int center_pos = (g_tui.term_cols - model_len) / 2;
    if (center_pos < 20)
        center_pos = 20;
    mvwprintw(g_tui.win_status, 0, center_pos, "%s", g_tui.status_model);

    /* Right side: message count and tokens. */
    char right_info[64];
    snprintf(right_info, sizeof(right_info), "msgs:%d tokens:%d ",
             g_tui.msg_count, g_tui.total_tokens);
    int right_pos = g_tui.term_cols - (int)strlen(right_info) - 1;
    if (right_pos > center_pos + model_len + 2)
        mvwprintw(g_tui.win_status, 0, right_pos, "%s", right_info);

    wattroff(g_tui.win_status, COLOR_PAIR(CP_STATUS_BAR));
    wnoutrefresh(g_tui.win_status);
}

static void tui_render_input(void)
{
    werase(g_tui.win_input);

    /* Draw border. */
    wattron(g_tui.win_input, COLOR_PAIR(CP_INPUT_BORDER));
    box(g_tui.win_input, 0, 0);
    wattroff(g_tui.win_input, COLOR_PAIR(CP_INPUT_BORDER));

    /* Prompt label. */
    wattron(g_tui.win_input, COLOR_PAIR(CP_USER) | A_BOLD);
    mvwprintw(g_tui.win_input, 1, 1, "> ");
    wattroff(g_tui.win_input, COLOR_PAIR(CP_USER) | A_BOLD);

    /* Input text. */
    int input_width = g_tui.term_cols - 5; /* borders + prompt. */
    if (input_width < 1)
        input_width = 1;

    /* Calculate visible portion of input. */
    int vis_start = 0;
    if (g_tui.input_pos > input_width)
        vis_start = g_tui.input_pos - input_width;

    for (int i = 0; i < input_width && (vis_start + i) < g_tui.input_len; i++) {
        mvwaddch(g_tui.win_input, 1, 3 + i,
                 (chtype)(unsigned char)g_tui.input_buf[vis_start + i]);
    }

    /* Position cursor. */
    int cursor_x = 3 + (g_tui.input_pos - vis_start);
    if (cursor_x >= g_tui.term_cols - 1)
        cursor_x = g_tui.term_cols - 2;
    wmove(g_tui.win_input, 1, cursor_x);

    wnoutrefresh(g_tui.win_input);
}

static void tui_render(void)
{
    tui_render_chat();
    tui_render_status();
    tui_render_input();
    doupdate();
    g_tui.needs_redraw = false;
}

/* ---- Key handling ------------------------------------------------------- */

static void tui_handle_key(int ch)
{
    switch (ch) {
    case ERR:
        /* Timeout, no key pressed. */
        break;

    case KEY_RESIZE:
        tui_resize();
        break;

    /* Ctrl-C: quit. */
    case 3:
        g_tui.running = false;
        break;

    /* Ctrl-L: redraw. */
    case 12:
        clearok(curscr, TRUE);
        g_tui.needs_redraw = true;
        break;

    /* Enter: send message. */
    case '\n':
    case '\r':
    case KEY_ENTER:
        tui_send_message();
        break;

    /* Backspace. */
    case KEY_BACKSPACE:
    case 127:
    case 8:
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

    /* Delete. */
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

    /* Left arrow. */
    case KEY_LEFT:
        if (g_tui.input_pos > 0) {
            g_tui.input_pos--;
            g_tui.needs_redraw = true;
        }
        break;

    /* Right arrow. */
    case KEY_RIGHT:
        if (g_tui.input_pos < g_tui.input_len) {
            g_tui.input_pos++;
            g_tui.needs_redraw = true;
        }
        break;

    /* Home. */
    case KEY_HOME:
    case 1: /* Ctrl-A */
        g_tui.input_pos = 0;
        g_tui.needs_redraw = true;
        break;

    /* End. */
    case KEY_END:
    case 5: /* Ctrl-E */
        g_tui.input_pos = g_tui.input_len;
        g_tui.needs_redraw = true;
        break;

    /* Ctrl-U: clear input line. */
    case 21:
        g_tui.input_len = 0;
        g_tui.input_pos = 0;
        g_tui.input_buf[0] = '\0';
        g_tui.needs_redraw = true;
        break;

    /* Ctrl-W: delete word backward. */
    case 23: {
        if (g_tui.input_pos > 0) {
            int end = g_tui.input_pos;
            /* Skip trailing spaces. */
            while (g_tui.input_pos > 0 &&
                   g_tui.input_buf[g_tui.input_pos - 1] == ' ')
                g_tui.input_pos--;
            /* Delete word. */
            while (g_tui.input_pos > 0 &&
                   g_tui.input_buf[g_tui.input_pos - 1] != ' ')
                g_tui.input_pos--;
            int deleted = end - g_tui.input_pos;
            memmove(&g_tui.input_buf[g_tui.input_pos],
                    &g_tui.input_buf[end],
                    (size_t)(g_tui.input_len - end));
            g_tui.input_len -= deleted;
            g_tui.input_buf[g_tui.input_len] = '\0';
            g_tui.needs_redraw = true;
        }
        break;
    }

    /* Page Up: scroll chat history up. */
    case KEY_PPAGE: {
        int chat_height = g_tui.term_rows - INPUT_HEIGHT - STATUS_HEIGHT;
        g_tui.scroll_offset += chat_height / 2;
        int max_scroll = g_tui.display_count -
                         (g_tui.term_rows - INPUT_HEIGHT - STATUS_HEIGHT);
        if (max_scroll < 0)
            max_scroll = 0;
        if (g_tui.scroll_offset > max_scroll)
            g_tui.scroll_offset = max_scroll;
        g_tui.needs_redraw = true;
        break;
    }

    /* Page Down: scroll chat history down. */
    case KEY_NPAGE: {
        int chat_height = g_tui.term_rows - INPUT_HEIGHT - STATUS_HEIGHT;
        g_tui.scroll_offset -= chat_height / 2;
        if (g_tui.scroll_offset < 0)
            g_tui.scroll_offset = 0;
        g_tui.needs_redraw = true;
        break;
    }

    /* Regular character input. */
    default:
        if (ch >= 32 && ch < 127 && g_tui.input_len < MAX_INPUT_LEN - 1) {
            /* Insert at cursor position. */
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

/* ---- Usage -------------------------------------------------------------- */

static void usage(void)
{
    printf(
        "Usage: clawd-tui [options]\n"
        "\n"
        "Options:\n"
        "  -c, --config <path>   Configuration file path\n"
        "  -h, --help            Show this help\n"
        "\n"
        "Keyboard shortcuts:\n"
        "  Enter        Send message\n"
        "  Ctrl-C       Quit\n"
        "  Ctrl-L       Redraw screen\n"
        "  Ctrl-U       Clear input line\n"
        "  Ctrl-W       Delete word backward\n"
        "  Ctrl-A       Move to beginning of line\n"
        "  Ctrl-E       Move to end of line\n"
        "  Page Up      Scroll chat history up\n"
        "  Page Down    Scroll chat history down\n"
        "\n"
        "Chat commands:\n"
        "  /quit, /exit   Exit the TUI\n"
        "  /clear          Clear chat history\n"
        "  /reconnect      Reconnect to gateway\n"
        "  /help           Show help\n"
        "\n"
    );
}

/* ---- Main --------------------------------------------------------------- */

int main(int argc, char **argv)
{
    const char *config_path = NULL;

    static struct option long_options[] = {
        {"config", required_argument, NULL, 'c'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,     0,                 NULL,  0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "c:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'c':
            config_path = optarg;
            break;
        case 'h':
            usage();
            return 0;
        default:
            fprintf(stderr, "Try 'clawd-tui --help' for more information.\n");
            return 1;
        }
    }

    /* Load configuration. */
    memset(&g_tui, 0, sizeof(g_tui));
    if (config_path) {
        if (clawd_config_load(config_path, &g_tui.cfg) != 0) {
            fprintf(stderr, "clawd-tui: failed to load config: %s\n",
                    config_path);
            return 1;
        }
    } else {
        clawd_config_load_default(&g_tui.cfg);
    }
    clawd_config_merge_env(&g_tui.cfg);

    /* Initialize logging (to file, not stderr, since we own the terminal). */
    clawd_log_init("clawd-tui", CLAWD_LOG_WARN);
    if (g_tui.cfg.logging.file) {
        FILE *logfp = fopen(g_tui.cfg.logging.file, "a");
        if (logfp)
            clawd_log_set_file(logfp);
    }

    /* Initialize TUI. */
    tui_init();

    /* Attempt initial gateway connection. */
    tui_connect_gateway();

    /* Main loop. */
    while (g_tui.running) {
        /* Check for async response completion. */
        if (g_tui.waiting) {
            pthread_mutex_lock(&g_tui.async_lock);
            if (g_tui.response_ready) {
                g_tui.waiting = false;
                if (g_tui.pending_response) {
                    if (g_tui.response_error) {
                        tui_add_message(MSG_ERROR, g_tui.pending_response);
                        free(g_tui.pending_response);
                    } else {
                        /* Start streaming text reveal. */
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

        /* Handle streaming text reveal (char-by-char effect). */
        if (g_tui.stream_text) {
            int total_len = (int)strlen(g_tui.stream_text);
            int remaining = total_len - g_tui.stream_pos;
            if (remaining > 0) {
                int advance = 8;
                if (total_len > 2000) advance = 24;
                else if (total_len > 1000) advance = 16;
                if (advance > remaining) advance = remaining;
                g_tui.stream_pos += advance;
                /* Update the message text to show revealed portion. */
                chat_message_t *msg = &g_tui.messages[g_tui.stream_msg_idx];
                free(msg->text);
                char *partial = malloc((size_t)g_tui.stream_pos + 1);
                if (partial) {
                    memcpy(partial, g_tui.stream_text,
                           (size_t)g_tui.stream_pos);
                    partial[g_tui.stream_pos] = '\0';
                    msg->text = partial;
                } else {
                    msg->text = strdup(g_tui.stream_text);
                    g_tui.stream_pos = total_len;
                }
                g_tui.needs_redraw = true;
            } else {
                /* Streaming complete. */
                free(g_tui.stream_text);
                g_tui.stream_text = NULL;
                g_tui.needs_redraw = true;
            }
        }

        /* Adjust refresh rate: faster during streaming/thinking. */
        if (g_tui.stream_text || g_tui.waiting)
            timeout(16);   /* ~60fps for smooth animation. */
        else
            timeout(100);  /* Normal idle rate. */

        if (g_tui.needs_redraw)
            tui_render();

        int ch = getch();
        if (ch != ERR)
            tui_handle_key(ch);
    }

    /* Clean up. */
    tui_destroy();
    clawd_config_free(&g_tui.cfg);

    return 0;
}
