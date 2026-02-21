/*
 * kelp-linux :: kelp-gateway
 * main.c - Gateway server: HTTP API, WebSocket, and Unix socket interface
 *
 * Usage: kelp-gateway [options]
 * Options:
 *   -c, --config <path>   Config file
 *   -l, --listen <addr>   Listen address (default: 127.0.0.1)
 *   -p, --port <port>     Listen port (default: 3000)
 *   -s, --socket <path>   Unix socket path
 *   -d, --daemon          Daemonize
 *   -h, --help            Help
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/kelp.h>
#include <kelp/config.h>
#include <kelp/paths.h>
#include <kelp/http.h>
#include <kelp/signals.h>
#include <kelp/audit.h>

#ifdef HAVE_AGENTS
#include <kelp/agent.h>
#include <kelp/provider.h>
#endif

#include <cjson/cJSON.h>

#include <openssl/evp.h>

#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/epoll.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/event.h>
#endif

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#ifdef __linux__
#include <kelp/kernel.h>
#endif

#include <poll.h>

#include <microhttpd.h>

/* ---- Version ------------------------------------------------------------ */

#define KELP_GATEWAY_VERSION "0.1.0"

/* ---- Limits ------------------------------------------------------------- */

#define MAX_SESSIONS          256
#define MAX_POST_DATA         (16 * 1024 * 1024) /* 16 MiB */
#define UNIX_BACKLOG          16
#define UNIX_BUF_SIZE         65536
#define THREAD_POOL_SIZE      8

/* ---- WebSocket constants ------------------------------------------------ */

#define WS_GUID               "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_MAX_FRAME_SIZE     (1 * 1024 * 1024)
#define WS_OPCODE_TEXT        0x01
#define WS_OPCODE_BINARY      0x02
#define WS_OPCODE_CLOSE       0x08
#define WS_OPCODE_PING        0x09
#define WS_OPCODE_PONG        0x0A

/* ---- Global state ------------------------------------------------------- */

static kelp_config_t        g_cfg;
static const char           *g_listen_addr   = "127.0.0.1";
static int                   g_port          = 3000;
static char                 *g_socket_path   = NULL;
static bool                  g_daemonize     = false;
static volatile sig_atomic_t g_shutdown      = 0;
static time_t                g_start_time    = 0;

static struct MHD_Daemon    *g_httpd         = NULL;
static int                   g_unix_fd       = -1;
static char                  g_pidfile[512]  = {0};

/* WebSocket listener (separate TCP socket on g_port + 1) */
static int                   g_ws_fd         = -1;
static int                   g_ws_port       = 0;

#ifdef __linux__
static int                   g_kernel_fd     = -1;
static pthread_t             g_kernel_thread;
static bool                  g_kernel_thread_running = false;
#endif

#ifdef HAVE_AGENTS
static kelp_provider_t     *g_provider      = NULL;
static kelp_tool_ctx_t     *g_tools         = NULL;
#endif

/* ---- Session tracking (with conversation history) ----------------------- */

#define MAX_HISTORY_MESSAGES  50   /* per session */

typedef struct {
    char     id[64];
    char     channel_id[128];      /* channel or DM identifier */
    char     user_id[128];         /* user identifier */
    time_t   created;
    time_t   last_active;
    bool     active;
    /* Conversation history: circular buffer of role+content pairs */
    struct {
        char *role;
        char *content;
    } history[MAX_HISTORY_MESSAGES];
    int      history_count;
#ifdef HAVE_AGENTS
    kelp_provider_t *provider;
    kelp_tool_ctx_t *tools;
    kelp_agent_t    *agent;
#endif
} gateway_session_t;

static gateway_session_t g_sessions[MAX_SESSIONS];
static pthread_mutex_t   g_sessions_lock = PTHREAD_MUTEX_INITIALIZER;

static void session_clear_history(gateway_session_t *s)
{
    for (int i = 0; i < s->history_count; i++) {
        free(s->history[i].role);
        free(s->history[i].content);
        s->history[i].role = NULL;
        s->history[i].content = NULL;
    }
    s->history_count = 0;
#ifdef HAVE_AGENTS
    if (s->agent)   { kelp_agent_free(s->agent);     s->agent = NULL; }
    if (s->tools)   { kelp_tool_ctx_free(s->tools);   s->tools = NULL; }
    if (s->provider) { kelp_provider_free(s->provider); s->provider = NULL; }
#endif
}

static void session_add_message(gateway_session_t *s,
                                 const char *role, const char *content)
{
    if (s->history_count >= MAX_HISTORY_MESSAGES) {
        /* Drop oldest message */
        free(s->history[0].role);
        free(s->history[0].content);
        memmove(&s->history[0], &s->history[1],
                (MAX_HISTORY_MESSAGES - 1) * sizeof(s->history[0]));
        s->history_count = MAX_HISTORY_MESSAGES - 1;
    }
    s->history[s->history_count].role    = strdup(role);
    s->history[s->history_count].content = strdup(content);
    s->history_count++;
    s->last_active = time(NULL);
}

static gateway_session_t *session_find(const char *channel_id,
                                        const char *user_id)
{
    if (!channel_id) return NULL;
    const char *uid = user_id ? user_id : "";

    pthread_mutex_lock(&g_sessions_lock);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].active &&
            strcmp(g_sessions[i].channel_id, channel_id) == 0 &&
            strcmp(g_sessions[i].user_id, uid) == 0) {
            pthread_mutex_unlock(&g_sessions_lock);
            return &g_sessions[i];
        }
    }
    pthread_mutex_unlock(&g_sessions_lock);
    return NULL;
}

static gateway_session_t *session_find_or_create(const char *channel_id,
                                                   const char *user_id)
{
    gateway_session_t *s = session_find(channel_id, user_id);
    if (s) return s;

    const char *uid = user_id ? user_id : "";

    pthread_mutex_lock(&g_sessions_lock);
    /* Find oldest inactive, or evict LRU if full */
    int slot = -1;
    time_t oldest = 0;
    int oldest_slot = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].active) {
            slot = i;
            break;
        }
        if (oldest == 0 || g_sessions[i].last_active < oldest) {
            oldest = g_sessions[i].last_active;
            oldest_slot = i;
        }
    }
    if (slot < 0) {
        /* Evict LRU session */
        session_clear_history(&g_sessions[oldest_slot]);
        slot = oldest_slot;
    }

    gateway_session_t *ns = &g_sessions[slot];
    memset(ns, 0, sizeof(*ns));
    ns->active = true;
    ns->created = time(NULL);
    ns->last_active = ns->created;
    snprintf(ns->id, sizeof(ns->id), "sess_%08x%08x",
             (unsigned)ns->created, (unsigned)slot);
    snprintf(ns->channel_id, sizeof(ns->channel_id), "%s",
             channel_id ? channel_id : "");
    snprintf(ns->user_id, sizeof(ns->user_id), "%s", uid);
    pthread_mutex_unlock(&g_sessions_lock);
    return ns;
}

static gateway_session_t *session_create(void)
{
    return session_find_or_create("_anonymous_", "_anonymous_");
}

static int session_count_active(void)
{
    int count = 0;
    pthread_mutex_lock(&g_sessions_lock);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].active)
            count++;
    }
    pthread_mutex_unlock(&g_sessions_lock);
    return count;
}

/* ---- HTTP request context ----------------------------------------------- */

typedef struct {
    kelp_str_t post_data;
    bool        too_large;
} http_request_ctx_t;

/* ---- Signal handling ---------------------------------------------------- */

static void on_shutdown_signal(int signo, void *userdata)
{
    (void)userdata;
    KELP_INFO("received signal %d, initiating shutdown", signo);
    g_shutdown = 1;
}

/* ---- Helper: JSON error response ---------------------------------------- */

static struct MHD_Response *json_error_response(int code, const char *message)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON *err = cJSON_AddObjectToObject(obj, "error");
    cJSON_AddNumberToObject(err, "code", code);
    cJSON_AddStringToObject(err, "message", message);
    cJSON_AddStringToObject(obj, "type", "error");

    char *body = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);

    struct MHD_Response *resp = MHD_create_response_from_buffer(
        strlen(body), body, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(resp, "Content-Type", "application/json");
    return resp;
}

/* ---- Helper: JSON success response -------------------------------------- */

static struct MHD_Response *json_success_response(cJSON *result)
{
    char *body = cJSON_PrintUnformatted(result);
    struct MHD_Response *resp = MHD_create_response_from_buffer(
        strlen(body), body, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(resp, "Content-Type", "application/json");
    return resp;
}


/* ---- Agent integration helpers ------------------------------------------ */

#ifdef HAVE_AGENTS

static kelp_provider_type_t resolve_provider_type(const char *name)
{
    if (!name)
        return KELP_PROVIDER_ANTHROPIC;
    if (strcmp(name, "openai") == 0)
        return KELP_PROVIDER_OPENAI;
    if (strcmp(name, "google") == 0)
        return KELP_PROVIDER_GOOGLE;
    if (strcmp(name, "ollama") == 0)
        return KELP_PROVIDER_OLLAMA;
    if (strcmp(name, "bedrock") == 0)
        return KELP_PROVIDER_BEDROCK;
    return KELP_PROVIDER_ANTHROPIC;
}


/* ---- SSE streaming infrastructure --------------------------------------- */

/* Single formatted SSE chunk in the queue */
typedef struct sse_chunk {
    char            *data;       /* malloc'd SSE text */
    size_t           len;
    size_t           offset;     /* bytes consumed by MHD so far */
    struct sse_chunk *next;
} sse_chunk_t;

/* Shared state between producer thread and MHD content reader */
typedef struct {
    pthread_mutex_t  lock;
    pthread_cond_t   cond;
    sse_chunk_t     *head;
    sse_chunk_t     *tail;
    bool             done;
    bool             error;
    char            *response;   /* accumulated text (for cleanup) */
} sse_stream_ctx_t;

typedef enum {
    SSE_FORMAT_OPENAI,     /* /v1/chat/completions */
    SSE_FORMAT_ANTHROPIC   /* /v1/messages */
} sse_format_t;

typedef struct {
    sse_stream_ctx_t *ctx;
    sse_format_t      format;
    const char       *completion_id;
    const char       *model;
} sse_cb_userdata_t;

typedef struct {
    sse_stream_ctx_t  *stream_ctx;
    sse_cb_userdata_t  cb_userdata;
    char              *user_message;
    char              *system_prompt;
    char              *model;
    int                max_tokens;
    kelp_message_t   *history;
} sse_producer_args_t;

static int sse_enqueue(sse_stream_ctx_t *ctx, char *data, size_t len)
{
    if (!data) return -1;
    sse_chunk_t *chunk = calloc(1, sizeof(*chunk));
    if (!chunk) { free(data); return -1; }
    chunk->data = data;
    chunk->len  = len;

    pthread_mutex_lock(&ctx->lock);
    if (ctx->tail) { ctx->tail->next = chunk; ctx->tail = chunk; }
    else           { ctx->head = ctx->tail = chunk; }
    pthread_cond_signal(&ctx->cond);
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

static ssize_t sse_content_reader(void *cls, uint64_t pos, char *buf, size_t max)
{
    (void)pos;
    sse_stream_ctx_t *ctx = cls;
    pthread_mutex_lock(&ctx->lock);

    while (!ctx->head && !ctx->done && !ctx->error) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;
        pthread_cond_timedwait(&ctx->cond, &ctx->lock, &ts);
    }

    if (!ctx->head) {
        pthread_mutex_unlock(&ctx->lock);
        return ctx->error ? MHD_CONTENT_READER_END_WITH_ERROR
                          : MHD_CONTENT_READER_END_OF_STREAM;
    }

    sse_chunk_t *chunk = ctx->head;
    size_t remaining = chunk->len - chunk->offset;
    size_t to_copy   = remaining < max ? remaining : max;
    memcpy(buf, chunk->data + chunk->offset, to_copy);
    chunk->offset += to_copy;

    if (chunk->offset >= chunk->len) {
        ctx->head = chunk->next;
        if (!ctx->head) ctx->tail = NULL;
        free(chunk->data);
        free(chunk);
    }
    pthread_mutex_unlock(&ctx->lock);
    return (ssize_t)to_copy;
}

static void sse_content_reader_free(void *cls)
{
    sse_stream_ctx_t *ctx = cls;
    pthread_mutex_lock(&ctx->lock);
    for (sse_chunk_t *c = ctx->head; c; ) {
        sse_chunk_t *next = c->next;
        free(c->data); free(c); c = next;
    }
    pthread_mutex_unlock(&ctx->lock);
    free(ctx->response);
    pthread_mutex_destroy(&ctx->lock);
    pthread_cond_destroy(&ctx->cond);
    free(ctx);
}

static int sse_stream_callback(const kelp_stream_event_t *event, void *userdata)
{
    sse_cb_userdata_t *ud = userdata;
    sse_stream_ctx_t *ctx = ud->ctx;

    if (strcmp(event->type, "text") == 0 && event->text) {
        if (ud->format == SSE_FORMAT_OPENAI) {
            cJSON *obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "id", ud->completion_id);
            cJSON_AddStringToObject(obj, "object", "chat.completion.chunk");
            cJSON *choices = cJSON_AddArrayToObject(obj, "choices");
            cJSON *choice = cJSON_CreateObject();
            cJSON_AddNumberToObject(choice, "index", 0);
            cJSON *delta = cJSON_CreateObject();
            cJSON_AddStringToObject(delta, "content", event->text);
            cJSON_AddItemToObject(choice, "delta", delta);
            cJSON_AddNullToObject(choice, "finish_reason");
            cJSON_AddItemToArray(choices, choice);

            char *json_str = cJSON_PrintUnformatted(obj);
            cJSON_Delete(obj);
            if (json_str) {
                char *buf = NULL;
                int n = asprintf(&buf, "data: %s\n\n", json_str);
                free(json_str);
                if (n > 0) sse_enqueue(ctx, buf, (size_t)n);
            }
        } else {
            /* Anthropic format: content_block_delta */
            cJSON *obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "type", "content_block_delta");
            cJSON_AddNumberToObject(obj, "index", 0);
            cJSON *delta = cJSON_CreateObject();
            cJSON_AddStringToObject(delta, "type", "text_delta");
            cJSON_AddStringToObject(delta, "text", event->text);
            cJSON_AddItemToObject(obj, "delta", delta);

            char *json_str = cJSON_PrintUnformatted(obj);
            cJSON_Delete(obj);
            if (json_str) {
                char *buf = NULL;
                int n = asprintf(&buf, "event: content_block_delta\ndata: %s\n\n",
                                 json_str);
                free(json_str);
                if (n > 0) sse_enqueue(ctx, buf, (size_t)n);
            }
        }
    } else if (strcmp(event->type, "done") == 0) {
        if (ud->format == SSE_FORMAT_OPENAI) {
            /* Final chunk with finish_reason */
            cJSON *obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "id", ud->completion_id);
            cJSON_AddStringToObject(obj, "object", "chat.completion.chunk");
            cJSON *choices = cJSON_AddArrayToObject(obj, "choices");
            cJSON *choice = cJSON_CreateObject();
            cJSON_AddNumberToObject(choice, "index", 0);
            cJSON *delta = cJSON_CreateObject();
            cJSON_AddItemToObject(choice, "delta", delta);
            cJSON_AddStringToObject(choice, "finish_reason", "stop");
            cJSON_AddItemToArray(choices, choice);

            char *json_str = cJSON_PrintUnformatted(obj);
            cJSON_Delete(obj);
            if (json_str) {
                char *buf = NULL;
                int n = asprintf(&buf, "data: %s\n\ndata: [DONE]\n\n", json_str);
                free(json_str);
                if (n > 0) sse_enqueue(ctx, buf, (size_t)n);
            }
        } else {
            /* Anthropic: content_block_stop + message_delta + message_stop */
            char *buf = NULL;
            int n = asprintf(&buf,
                "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n"
                "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":0}}\n\n"
                "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
            if (n > 0) sse_enqueue(ctx, buf, (size_t)n);
        }
    } else if (strcmp(event->type, "error") == 0) {
        pthread_mutex_lock(&ctx->lock);
        ctx->error = true;
        pthread_cond_signal(&ctx->cond);
        pthread_mutex_unlock(&ctx->lock);
    }
    return 0;
}

static char *gateway_agent_chat_full(
    const char        *user_message,
    const char        *system_prompt,
    kelp_message_t   *history,
    const char        *model,
    int                max_tokens,
    kelp_stream_cb    on_stream,
    void              *stream_userdata)
{
    if (!g_provider) return NULL;

    kelp_agent_opts_t opts = {
        .provider        = g_provider,
        .tools           = g_tools,
        .system_prompt   = system_prompt ? system_prompt
                               : "You are a helpful AI assistant.",
        .max_turns       = 10,
        .sandbox_tools   = g_cfg.security.sandbox_enabled,
        .model           = model,
        .max_tokens      = max_tokens,
        .on_stream       = on_stream,
        .stream_userdata = stream_userdata,
    };

    kelp_agent_t *agent = kelp_agent_new(&opts);
    if (!agent) return NULL;

    if (history) {
        if (kelp_agent_set_history(agent, history) != 0) {
            kelp_agent_free(agent);
            return NULL;
        }
    }

    char *response = NULL;
    int rc = kelp_agent_chat(agent, user_message, &response);
    kelp_agent_free(agent);

    if (rc != 0) {
        free(response);
        return NULL;
    }
    return response;
}

static void *sse_producer_thread(void *arg)
{
    sse_producer_args_t *args = arg;
    sse_stream_ctx_t *ctx = args->stream_ctx;

    char *response = gateway_agent_chat_full(
        args->user_message, args->system_prompt,
        args->history, args->model, args->max_tokens,
        sse_stream_callback, &args->cb_userdata);

    pthread_mutex_lock(&ctx->lock);
    ctx->response = response;
    if (!ctx->error) ctx->done = true;
    pthread_cond_signal(&ctx->cond);
    pthread_mutex_unlock(&ctx->lock);

    kelp_message_free(args->history);
    free(args->user_message);
    free(args->system_prompt);
    free(args->model);
    free(args);
    return NULL;
}

#endif /* HAVE_AGENTS */

/* ---- Route: POST /v1/chat/completions (OpenAI-compatible) --------------- */

static enum MHD_Result handle_chat_completions(
    struct MHD_Connection *conn, const char *post_data, size_t post_len)
{
    cJSON *req = cJSON_ParseWithLength(post_data, post_len);
    if (!req) {
        struct MHD_Response *resp = json_error_response(400, "invalid JSON");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    const char *model = kelp_json_get_string(req, "model");
    cJSON *messages = kelp_json_get_array(req, "messages");
    bool stream = kelp_json_get_bool(req, "stream", false);
    int max_tokens = kelp_json_get_int(req, "max_tokens", 4096);

    if (!messages) {
        cJSON_Delete(req);
        struct MHD_Response *resp = json_error_response(400, "missing 'messages' array");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    KELP_INFO("chat/completions: model=%s, messages=%d, stream=%s",
               model ? model : "(default)",
               cJSON_GetArraySize(messages),
               stream ? "true" : "false");

    gateway_session_t *sess = session_create();

    const char *effective_model = model ? model
        : (g_cfg.model.default_model
               ? g_cfg.model.default_model
               : "claude-sonnet-4-20250514");

#ifdef HAVE_AGENTS
    /* Extract last user message and build history from prior messages */
    const char *user_msg = NULL;
    int last_user_idx = -1;
    int arr_size = cJSON_GetArraySize(messages);
    for (int i = arr_size - 1; i >= 0; i--) {
        cJSON *m = cJSON_GetArrayItem(messages, i);
        const char *r = kelp_json_get_string(m, "role");
        if (r && strcmp(r, "user") == 0) {
            user_msg = kelp_json_get_string(m, "content");
            last_user_idx = i;
            break;
        }
    }

    if (!user_msg) {
        cJSON_Delete(req);
        struct MHD_Response *resp = json_error_response(400,
            "no user message found");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    /* Build history from messages [0, last_user_idx) */
    kelp_message_t *history = NULL;
    for (int i = 0; i < last_user_idx; i++) {
        cJSON *m = cJSON_GetArrayItem(messages, i);
        const char *role_str = kelp_json_get_string(m, "role");
        const char *content  = kelp_json_get_string(m, "content");
        if (!role_str) continue;
        kelp_role_t role;
        if      (strcmp(role_str, "user")      == 0) role = KELP_ROLE_USER;
        else if (strcmp(role_str, "assistant") == 0) role = KELP_ROLE_ASSISTANT;
        else if (strcmp(role_str, "system")    == 0) role = KELP_ROLE_SYSTEM;
        else continue;
        kelp_message_t *msg = kelp_message_new(role, content);
        if (msg) kelp_message_append(&history, msg);
    }

    /* SSE streaming path */
    if (stream && g_provider) {
        sse_stream_ctx_t *sctx = calloc(1, sizeof(*sctx));
        if (!sctx) {
            kelp_message_free(history);
            cJSON_Delete(req);
            struct MHD_Response *resp = json_error_response(500,
                "allocation failure");
            enum MHD_Result ret = MHD_queue_response(conn,
                MHD_HTTP_INTERNAL_SERVER_ERROR, resp);
            MHD_destroy_response(resp);
            return ret;
        }
        pthread_mutex_init(&sctx->lock, NULL);
        pthread_cond_init(&sctx->cond, NULL);

        sse_producer_args_t *pargs = calloc(1, sizeof(*pargs));
        if (!pargs) {
            kelp_message_free(history);
            pthread_mutex_destroy(&sctx->lock);
            pthread_cond_destroy(&sctx->cond);
            free(sctx);
            cJSON_Delete(req);
            struct MHD_Response *resp = json_error_response(500,
                "allocation failure");
            enum MHD_Result ret = MHD_queue_response(conn,
                MHD_HTTP_INTERNAL_SERVER_ERROR, resp);
            MHD_destroy_response(resp);
            return ret;
        }
        pargs->stream_ctx   = sctx;
        pargs->user_message = strdup(user_msg);
        pargs->system_prompt = NULL;
        pargs->model        = effective_model ? strdup(effective_model) : NULL;
        pargs->max_tokens   = max_tokens;
        pargs->history      = history;  /* ownership transferred */
        pargs->cb_userdata.ctx           = sctx;
        pargs->cb_userdata.format        = SSE_FORMAT_OPENAI;
        pargs->cb_userdata.completion_id = sess ? sess->id : "chatcmpl-0";
        pargs->cb_userdata.model         = pargs->model;

        struct MHD_Response *resp = MHD_create_response_from_callback(
            MHD_SIZE_UNKNOWN, 4096, sse_content_reader, sctx,
            sse_content_reader_free);
        MHD_add_response_header(resp, "Content-Type", "text/event-stream");
        MHD_add_response_header(resp, "Cache-Control", "no-cache");
        MHD_add_response_header(resp, "X-Accel-Buffering", "no");

        /* Initial ping to flush headers */
        char *ping = strdup(": ping\n\n");
        if (ping) sse_enqueue(sctx, ping, strlen(ping));

        pthread_t tid;
        if (pthread_create(&tid, NULL, sse_producer_thread, pargs) == 0) {
            pthread_detach(tid);
        } else {
            /* Thread creation failed — signal error */
            pthread_mutex_lock(&sctx->lock);
            sctx->error = true;
            pthread_cond_signal(&sctx->cond);
            pthread_mutex_unlock(&sctx->lock);
            free(pargs->user_message);
            free(pargs->system_prompt);
            free(pargs->model);
            kelp_message_free(pargs->history);
            free(pargs);
        }

        cJSON_Delete(req);
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    /* Non-streaming path */
    char *agent_response = gateway_agent_chat_full(
        user_msg, NULL, history, effective_model, max_tokens, NULL, NULL);
    kelp_message_free(history);

    const char *response_content = agent_response ? agent_response
        : "[kelp-gateway] Provider call failed.";
#else
    (void)max_tokens; (void)stream;
    const char *response_content = "[kelp-gateway] Request received. "
                       "Agent processing not yet connected.";
#endif

    cJSON *resp_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(resp_obj, "id",
                            sess ? sess->id : "sess_unknown");
    cJSON_AddStringToObject(resp_obj, "object", "chat.completion");
    cJSON_AddNumberToObject(resp_obj, "created", (double)time(NULL));
    cJSON_AddStringToObject(resp_obj, "model", effective_model);

    cJSON *choices = cJSON_AddArrayToObject(resp_obj, "choices");
    cJSON *choice = cJSON_CreateObject();
    cJSON_AddNumberToObject(choice, "index", 0);

    cJSON *message = cJSON_CreateObject();
    cJSON_AddStringToObject(message, "role", "assistant");
    cJSON_AddStringToObject(message, "content", response_content);
    cJSON_AddItemToObject(choice, "message", message);
    cJSON_AddStringToObject(choice, "finish_reason", "stop");
    cJSON_AddItemToArray(choices, choice);

    cJSON *usage = cJSON_AddObjectToObject(resp_obj, "usage");
    cJSON_AddNumberToObject(usage, "prompt_tokens", 0);
    cJSON_AddNumberToObject(usage, "completion_tokens", 0);
    cJSON_AddNumberToObject(usage, "total_tokens", 0);

    struct MHD_Response *resp = json_success_response(resp_obj);
    cJSON_Delete(resp_obj);
    cJSON_Delete(req);

#ifdef HAVE_AGENTS
    free(agent_response);
#endif

    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
}

/* ---- Route: POST /v1/messages (Anthropic-compatible) -------------------- */

static enum MHD_Result handle_messages(
    struct MHD_Connection *conn, const char *post_data, size_t post_len)
{
    cJSON *req = cJSON_ParseWithLength(post_data, post_len);
    if (!req) {
        struct MHD_Response *resp = json_error_response(400, "invalid JSON");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    const char *model = kelp_json_get_string(req, "model");
    int max_tokens = kelp_json_get_int(req, "max_tokens", 4096);
    cJSON *messages = kelp_json_get_array(req, "messages");
    bool stream = kelp_json_get_bool(req, "stream", false);

    if (!messages) {
        cJSON_Delete(req);
        struct MHD_Response *resp = json_error_response(400, "missing 'messages' array");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    KELP_INFO("messages: model=%s, max_tokens=%d, messages=%d, stream=%s",
               model ? model : "(default)", max_tokens,
               cJSON_GetArraySize(messages),
               stream ? "true" : "false");

    gateway_session_t *sess = session_create();
    const char *effective_model = model ? model
        : (g_cfg.model.default_model ? g_cfg.model.default_model
               : "claude-sonnet-4-20250514");

#ifdef HAVE_AGENTS
    /* Extract last user message and build history from prior messages */
    const char *user_msg = NULL;
    int last_user_idx = -1;
    int arr_size = cJSON_GetArraySize(messages);
    for (int i = arr_size - 1; i >= 0; i--) {
        cJSON *m = cJSON_GetArrayItem(messages, i);
        const char *r = kelp_json_get_string(m, "role");
        if (r && strcmp(r, "user") == 0) {
            user_msg = kelp_json_get_string(m, "content");
            last_user_idx = i;
            break;
        }
    }

    if (!user_msg) {
        cJSON_Delete(req);
        struct MHD_Response *resp = json_error_response(400,
            "no user message found");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    /* Build history from messages [0, last_user_idx) */
    kelp_message_t *history = NULL;
    for (int i = 0; i < last_user_idx; i++) {
        cJSON *m = cJSON_GetArrayItem(messages, i);
        const char *role_str = kelp_json_get_string(m, "role");
        const char *content  = kelp_json_get_string(m, "content");
        if (!role_str) continue;
        kelp_role_t role;
        if      (strcmp(role_str, "user")      == 0) role = KELP_ROLE_USER;
        else if (strcmp(role_str, "assistant") == 0) role = KELP_ROLE_ASSISTANT;
        else if (strcmp(role_str, "system")    == 0) role = KELP_ROLE_SYSTEM;
        else continue;
        kelp_message_t *msg = kelp_message_new(role, content);
        if (msg) kelp_message_append(&history, msg);
    }

    /* SSE streaming path */
    if (stream && g_provider) {
        sse_stream_ctx_t *sctx = calloc(1, sizeof(*sctx));
        if (!sctx) {
            kelp_message_free(history);
            cJSON_Delete(req);
            struct MHD_Response *resp = json_error_response(500,
                "allocation failure");
            enum MHD_Result ret = MHD_queue_response(conn,
                MHD_HTTP_INTERNAL_SERVER_ERROR, resp);
            MHD_destroy_response(resp);
            return ret;
        }
        pthread_mutex_init(&sctx->lock, NULL);
        pthread_cond_init(&sctx->cond, NULL);

        sse_producer_args_t *pargs = calloc(1, sizeof(*pargs));
        if (!pargs) {
            kelp_message_free(history);
            pthread_mutex_destroy(&sctx->lock);
            pthread_cond_destroy(&sctx->cond);
            free(sctx);
            cJSON_Delete(req);
            struct MHD_Response *resp = json_error_response(500,
                "allocation failure");
            enum MHD_Result ret = MHD_queue_response(conn,
                MHD_HTTP_INTERNAL_SERVER_ERROR, resp);
            MHD_destroy_response(resp);
            return ret;
        }
        pargs->stream_ctx   = sctx;
        pargs->user_message = strdup(user_msg);
        pargs->system_prompt = NULL;
        pargs->model        = effective_model ? strdup(effective_model) : NULL;
        pargs->max_tokens   = max_tokens;
        pargs->history      = history;  /* ownership transferred */
        pargs->cb_userdata.ctx           = sctx;
        pargs->cb_userdata.format        = SSE_FORMAT_ANTHROPIC;
        pargs->cb_userdata.completion_id = sess ? sess->id : "msg_0";
        pargs->cb_userdata.model         = pargs->model;

        struct MHD_Response *resp = MHD_create_response_from_callback(
            MHD_SIZE_UNKNOWN, 4096, sse_content_reader, sctx,
            sse_content_reader_free);
        MHD_add_response_header(resp, "Content-Type", "text/event-stream");
        MHD_add_response_header(resp, "Cache-Control", "no-cache");
        MHD_add_response_header(resp, "X-Accel-Buffering", "no");

        /* Initial ping to flush headers */
        char *ping = strdup(": ping\n\n");
        if (ping) sse_enqueue(sctx, ping, strlen(ping));

        /* Anthropic preamble: message_start + content_block_start */
        {
            cJSON *ms = cJSON_CreateObject();
            cJSON_AddStringToObject(ms, "type", "message_start");
            cJSON *msg_obj = cJSON_CreateObject();
            cJSON_AddStringToObject(msg_obj, "id", sess ? sess->id : "msg_0");
            cJSON_AddStringToObject(msg_obj, "type", "message");
            cJSON_AddStringToObject(msg_obj, "role", "assistant");
            cJSON_AddStringToObject(msg_obj, "model",
                                    effective_model ? effective_model : "");
            cJSON_AddItemToObject(ms, "message", msg_obj);
            char *ms_json = cJSON_PrintUnformatted(ms);
            cJSON_Delete(ms);
            if (ms_json) {
                char *buf = NULL;
                int n = asprintf(&buf,
                    "event: message_start\ndata: %s\n\n"
                    "event: content_block_start\n"
                    "data: {\"type\":\"content_block_start\",\"index\":0,"
                    "\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
                    ms_json);
                free(ms_json);
                if (n > 0) sse_enqueue(sctx, buf, (size_t)n);
            }
        }

        pthread_t tid;
        if (pthread_create(&tid, NULL, sse_producer_thread, pargs) == 0) {
            pthread_detach(tid);
        } else {
            pthread_mutex_lock(&sctx->lock);
            sctx->error = true;
            pthread_cond_signal(&sctx->cond);
            pthread_mutex_unlock(&sctx->lock);
            free(pargs->user_message);
            free(pargs->system_prompt);
            free(pargs->model);
            kelp_message_free(pargs->history);
            free(pargs);
        }

        cJSON_Delete(req);
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    /* Non-streaming path */
    char *agent_response = gateway_agent_chat_full(
        user_msg, NULL, history, effective_model, max_tokens, NULL, NULL);
    kelp_message_free(history);

    const char *response_text = agent_response ? agent_response
        : "[kelp-gateway] Provider call failed.";
    const char *stop_reason = "end_turn";
#else
    (void)max_tokens; (void)stream;
    const char *response_text = "[kelp-gateway] Request received. "
                    "Agent processing not yet connected.";
    const char *stop_reason = "end_turn";
#endif

    cJSON *resp_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(resp_obj, "id",
                            sess ? sess->id : "msg_unknown");
    cJSON_AddStringToObject(resp_obj, "type", "message");
    cJSON_AddStringToObject(resp_obj, "role", "assistant");
    cJSON_AddStringToObject(resp_obj, "model", effective_model);

    cJSON *content = cJSON_AddArrayToObject(resp_obj, "content");
    cJSON *block = cJSON_CreateObject();
    cJSON_AddStringToObject(block, "type", "text");
    cJSON_AddStringToObject(block, "text", response_text);
    cJSON_AddItemToArray(content, block);

    cJSON_AddStringToObject(resp_obj, "stop_reason", stop_reason);
    cJSON_AddNullToObject(resp_obj, "stop_sequence");

    cJSON *usage = cJSON_AddObjectToObject(resp_obj, "usage");
    cJSON_AddNumberToObject(usage, "input_tokens", 0);
    cJSON_AddNumberToObject(usage, "output_tokens", 0);

    struct MHD_Response *resp = json_success_response(resp_obj);
    cJSON_Delete(resp_obj);
    cJSON_Delete(req);

#ifdef HAVE_AGENTS
    free(agent_response);
#endif

    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
}

/* ---- Route: GET /v1/health ---------------------------------------------- */

static enum MHD_Result handle_health(struct MHD_Connection *conn)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "status", "ok");
    cJSON_AddStringToObject(obj, "version", KELP_GATEWAY_VERSION);
    cJSON_AddNumberToObject(obj, "uptime", (double)(time(NULL) - g_start_time));
    cJSON_AddNumberToObject(obj, "active_sessions",
                            (double)session_count_active());

#ifdef __linux__
    cJSON_AddBoolToObject(obj, "kernel_connected", g_kernel_fd >= 0);
#else
    cJSON_AddBoolToObject(obj, "kernel_connected", false);
#endif

    struct MHD_Response *resp = json_success_response(obj);
    cJSON_Delete(obj);

    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
}

/* ---- Route: GET /v1/config ---------------------------------------------- */

static enum MHD_Result handle_config(struct MHD_Connection *conn)
{
    cJSON *obj = cJSON_CreateObject();

    cJSON *gw = cJSON_AddObjectToObject(obj, "gateway");
    cJSON_AddStringToObject(gw, "host",
                            g_cfg.gateway.host ? g_cfg.gateway.host : g_listen_addr);
    cJSON_AddNumberToObject(gw, "port", g_port);
    cJSON_AddBoolToObject(gw, "tls_enabled", g_cfg.gateway.tls_enabled);

    cJSON *mdl = cJSON_AddObjectToObject(obj, "model");
    cJSON_AddStringToObject(mdl, "default_provider",
                            g_cfg.model.default_provider
                                ? g_cfg.model.default_provider : "anthropic");
    cJSON_AddStringToObject(mdl, "default_model",
                            g_cfg.model.default_model
                                ? g_cfg.model.default_model : "(unset)");
    cJSON_AddNumberToObject(mdl, "max_tokens", g_cfg.model.max_tokens);
    cJSON_AddNumberToObject(mdl, "temperature", (double)g_cfg.model.temperature);

    cJSON *sec = cJSON_AddObjectToObject(obj, "security");
    cJSON_AddBoolToObject(sec, "sandbox_enabled", g_cfg.security.sandbox_enabled);

    struct MHD_Response *resp = json_success_response(obj);
    cJSON_Delete(obj);

    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
}

/* ---- Route: POST /v1/agent/chat ----------------------------------------- */

static enum MHD_Result handle_agent_chat(
    struct MHD_Connection *conn, const char *post_data, size_t post_len)
{
    cJSON *req = cJSON_ParseWithLength(post_data, post_len);
    if (!req) {
        struct MHD_Response *resp = json_error_response(400, "invalid JSON");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    const char *message = kelp_json_get_string(req, "message");
    if (!message) {
        cJSON_Delete(req);
        struct MHD_Response *resp = json_error_response(400, "missing 'message' field");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    const char *session_id = kelp_json_get_string(req, "session_id");
    bool use_tools = kelp_json_get_bool(req, "use_tools", true);

    (void)session_id;

    KELP_INFO("agent/chat: message_len=%zu, use_tools=%s",
               strlen(message), use_tools ? "true" : "false");

    const char *response_content = NULL;
    const char *stop_reason = "end_turn";

#ifdef HAVE_AGENTS
    (void)use_tools;
    char *agent_response = gateway_agent_chat_full(
        message, NULL, NULL, NULL, 0, NULL, NULL);
    response_content = agent_response ? agent_response
        : "[kelp-gateway] Agent call failed.";
#else
    (void)use_tools;
    response_content = "[kelp-gateway] Agent chat received. "
                       "Tool-use routing not yet connected.";
#endif

    cJSON *resp_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(resp_obj, "role", "assistant");
    cJSON_AddStringToObject(resp_obj, "content", response_content);
    cJSON_AddStringToObject(resp_obj, "stop_reason", stop_reason);

    struct MHD_Response *resp = json_success_response(resp_obj);
    cJSON_Delete(resp_obj);
    cJSON_Delete(req);

#ifdef HAVE_AGENTS
    free(agent_response);
#endif

    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
}

/* ---- Route: GET /v1/sessions -------------------------------------------- */

static enum MHD_Result handle_sessions(struct MHD_Connection *conn)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON *arr = cJSON_AddArrayToObject(obj, "sessions");

    pthread_mutex_lock(&g_sessions_lock);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].active) {
            cJSON *s = cJSON_CreateObject();
            cJSON_AddStringToObject(s, "id", g_sessions[i].id);
            cJSON_AddNumberToObject(s, "created",
                                    (double)g_sessions[i].created);
            cJSON_AddNumberToObject(s, "last_active",
                                    (double)g_sessions[i].last_active);
            cJSON_AddItemToArray(arr, s);
        }
    }
    pthread_mutex_unlock(&g_sessions_lock);

    struct MHD_Response *resp = json_success_response(obj);
    cJSON_Delete(obj);

    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
}

/* ---- MHD request handler ------------------------------------------------ */

static enum MHD_Result http_handler(
    void *cls,
    struct MHD_Connection *conn,
    const char *url,
    const char *method,
    const char *version,
    const char *upload_data,
    size_t *upload_data_size,
    void **con_cls)
{
    (void)cls;
    (void)version;

    /* First call: allocate per-connection context. */
    if (*con_cls == NULL) {
        http_request_ctx_t *ctx = calloc(1, sizeof(*ctx));
        if (!ctx)
            return MHD_NO;
        ctx->post_data = kelp_str_new();
        *con_cls = ctx;
        return MHD_YES;
    }

    http_request_ctx_t *ctx = *con_cls;

    /* Accumulate POST data. */
    if (*upload_data_size > 0) {
        if (ctx->post_data.len + *upload_data_size > MAX_POST_DATA) {
            ctx->too_large = true;
        } else {
            kelp_str_append(&ctx->post_data, upload_data, *upload_data_size);
        }
        *upload_data_size = 0;
        return MHD_YES;
    }

    /* All data received -- dispatch. */
    KELP_DEBUG("HTTP %s %s (body=%zu bytes)", method, url, ctx->post_data.len);

    if (ctx->too_large) {
        struct MHD_Response *resp = json_error_response(
            413, "request body too large");
        enum MHD_Result ret = MHD_queue_response(
            conn, MHD_HTTP_CONTENT_TOO_LARGE, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    enum MHD_Result result;

    /* Route: POST /v1/chat/completions */
    if (strcmp(method, "POST") == 0 &&
        strcmp(url, "/v1/chat/completions") == 0) {
        result = handle_chat_completions(conn,
                                         ctx->post_data.data,
                                         ctx->post_data.len);
    }
    /* Route: POST /v1/messages */
    else if (strcmp(method, "POST") == 0 &&
             strcmp(url, "/v1/messages") == 0) {
        result = handle_messages(conn,
                                 ctx->post_data.data,
                                 ctx->post_data.len);
    }
    /* Route: GET /v1/health */
    else if (strcmp(method, "GET") == 0 &&
             strcmp(url, "/v1/health") == 0) {
        result = handle_health(conn);
    }
    /* Route: GET /v1/config */
    else if (strcmp(method, "GET") == 0 &&
             strcmp(url, "/v1/config") == 0) {
        result = handle_config(conn);
    }
    /* Route: POST /v1/agent/chat */
    else if (strcmp(method, "POST") == 0 &&
             strcmp(url, "/v1/agent/chat") == 0) {
        result = handle_agent_chat(conn,
                                   ctx->post_data.data,
                                   ctx->post_data.len);
    }
    /* Route: GET /v1/sessions */
    else if (strcmp(method, "GET") == 0 &&
             strcmp(url, "/v1/sessions") == 0) {
        result = handle_sessions(conn);
    }
    /* 404 - Not Found */
    else {
        struct MHD_Response *resp = json_error_response(404, "not found");
        result = MHD_queue_response(conn, MHD_HTTP_NOT_FOUND, resp);
        MHD_destroy_response(resp);
    }

    return result;
}

/* ---- MHD connection completed callback ---------------------------------- */

static void http_completed(void *cls, struct MHD_Connection *conn,
                           void **con_cls,
                           enum MHD_RequestTerminationCode toe)
{
    (void)cls;
    (void)conn;
    (void)toe;

    http_request_ctx_t *ctx = *con_cls;
    if (ctx) {
        kelp_str_free(&ctx->post_data);
        free(ctx);
    }
    *con_cls = NULL;
}

/* ---- Unix socket server ------------------------------------------------- */

static int unix_socket_create(const char *path)
{
    /* Remove stale socket file. */
    unlink(path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        KELP_ERROR("socket(AF_UNIX): %s", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    if (strlen(path) >= sizeof(addr.sun_path)) {
        KELP_ERROR("socket path too long: %s", path);
        close(fd);
        return -1;
    }
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        KELP_ERROR("bind(%s): %s", path, strerror(errno));
        close(fd);
        return -1;
    }

    /* Set socket permissions: owner read/write only. */
    chmod(path, 0600);

    if (listen(fd, UNIX_BACKLOG) < 0) {
        KELP_ERROR("listen(%s): %s", path, strerror(errno));
        close(fd);
        unlink(path);
        return -1;
    }

    /* Set non-blocking. */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    KELP_INFO("Unix socket listening on %s", path);
    return fd;
}

/**
 * Dispatch a JSON-RPC request and return a malloc'd JSON response string.
 * Caller must free the returned string. Returns NULL on allocation failure.
 */
static char *jsonrpc_dispatch(const char *request_data, size_t request_len)
{
    (void)request_len;

    cJSON *req = kelp_json_parse(request_data);
    if (!req) {
        return strdup("{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32700,"
                      "\"message\":\"parse error\"},\"id\":null}");
    }

    const char *method = kelp_json_get_string(req, "method");
    int rpc_id = kelp_json_get_int(req, "id", 0);
    cJSON *params = kelp_json_get_object(req, "params");

    KELP_DEBUG("JSON-RPC: method=%s, id=%d", method ? method : "(null)", rpc_id);

    /* Build response. */
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "jsonrpc", "2.0");
    cJSON_AddNumberToObject(resp, "id", rpc_id);

    if (!method) {
        cJSON *err = cJSON_AddObjectToObject(resp, "error");
        cJSON_AddNumberToObject(err, "code", -32600);
        cJSON_AddStringToObject(err, "message", "invalid request: missing method");
    } else if (strcmp(method, "chat.send") == 0) {
        const char *message = params ? kelp_json_get_string(params, "message") : NULL;
        const char *channel_id = params ? kelp_json_get_string(params, "channel_id") : NULL;
        const char *user_id = params ? kelp_json_get_string(params, "user_id") : NULL;
        if (!message) {
            cJSON *err = cJSON_AddObjectToObject(resp, "error");
            cJSON_AddNumberToObject(err, "code", -32602);
            cJSON_AddStringToObject(err, "message", "missing 'message' parameter");
        } else {
            KELP_INFO("chat.send: len=%zu ch=%s user=%s",
                       strlen(message),
                       channel_id ? channel_id : "-",
                       user_id ? user_id : "-");

#ifdef HAVE_AGENTS
            /* Find or create session for this channel+user */
            gateway_session_t *sess = channel_id
                ? session_find_or_create(channel_id, user_id)
                : session_create();

            /* Lazily initialize agent with tools for this session */
            if (sess && !sess->agent) {
                kelp_provider_type_t ptype = resolve_provider_type(
                    g_cfg.model.default_provider);
                sess->provider = kelp_provider_new(ptype, g_cfg.model.api_key);
                if (sess->provider) {
                    sess->tools = kelp_tool_ctx_new("/tmp/kelp-workspace");
                    if (sess->tools)
                        kelp_tool_register_defaults(sess->tools);

                    kelp_agent_opts_t agent_opts = {
                        .provider       = sess->provider,
                        .tools          = sess->tools,
                        .system_prompt  = g_cfg.model.system_prompt,
                        .max_turns      = 10,
                        .sandbox_tools  = g_cfg.security.sandbox_enabled,
                        .on_stream      = NULL,
                        .stream_userdata = NULL,
                        .model          = g_cfg.model.default_model,
                        .max_tokens     = 0,
                    };
                    sess->agent = kelp_agent_new(&agent_opts);
                    if (sess->agent)
                        KELP_INFO("chat.send: created agent for session %s",
                                   sess->id);
                }
            }

            /* Run the agent loop (handles history + tool use internally) */
            char *agent_response = NULL;
            if (sess && sess->agent) {
                int rc = kelp_agent_chat(sess->agent, message,
                                          &agent_response);
                if (rc != 0)
                    KELP_ERROR("chat.send: agent chat failed (rc=%d)", rc);
            } else {
                KELP_ERROR("chat.send: no agent available for session");
            }

            cJSON *result = cJSON_AddObjectToObject(resp, "result");
            cJSON_AddStringToObject(result, "content",
                agent_response ? agent_response
                    : "[kelp-gateway] Agent call failed.");
            cJSON_AddStringToObject(result, "role", "assistant");
            cJSON_AddStringToObject(result, "stop_reason", "end_turn");
            free(agent_response);
#else
            cJSON *result = cJSON_AddObjectToObject(resp, "result");
            cJSON_AddStringToObject(result, "content",
                                    "[kelp-gateway] Message received. "
                                    "Agent processing not yet connected.");
            cJSON_AddStringToObject(result, "role", "assistant");
            cJSON_AddStringToObject(result, "stop_reason", "end_turn");
#endif
        }
    } else if (strcmp(method, "health") == 0) {
        cJSON *result = cJSON_AddObjectToObject(resp, "result");
        cJSON_AddStringToObject(result, "status", "ok");
        cJSON_AddStringToObject(result, "version", KELP_GATEWAY_VERSION);
        cJSON_AddNumberToObject(result, "uptime",
                                (double)(time(NULL) - g_start_time));
        cJSON_AddNumberToObject(result, "active_sessions",
                                (double)session_count_active());
    } else if (strcmp(method, "config.get") == 0) {
        const char *key = params ? kelp_json_get_string(params, "key") : NULL;
        if (!key) {
            cJSON *err = cJSON_AddObjectToObject(resp, "error");
            cJSON_AddNumberToObject(err, "code", -32602);
            cJSON_AddStringToObject(err, "message", "missing 'key' parameter");
        } else {
            const char *val = kelp_config_get_string(&g_cfg, key);
            cJSON *result = cJSON_AddObjectToObject(resp, "result");
            if (val)
                cJSON_AddStringToObject(result, "value", val);
            else
                cJSON_AddNullToObject(result, "value");
        }
    } else if (strcmp(method, "sessions.list") == 0) {
        cJSON *result = cJSON_AddObjectToObject(resp, "result");
        cJSON *arr = cJSON_AddArrayToObject(result, "sessions");
        pthread_mutex_lock(&g_sessions_lock);
        for (int i = 0; i < MAX_SESSIONS; i++) {
            if (g_sessions[i].active) {
                cJSON *s = cJSON_CreateObject();
                cJSON_AddStringToObject(s, "id", g_sessions[i].id);
                cJSON_AddItemToArray(arr, s);
            }
        }
        pthread_mutex_unlock(&g_sessions_lock);
    } else if (strcmp(method, "kernel.status") == 0) {
        cJSON *result = cJSON_AddObjectToObject(resp, "result");
#ifdef __linux__
        if (g_kernel_fd >= 0) {
            struct kelp_kstats kstats;
            if (kelp_kernel_get_stats(g_kernel_fd, &kstats) == 0) {
                cJSON_AddBoolToObject(result, "connected", true);
                cJSON_AddNumberToObject(result, "messages_processed",
                                        (double)kstats.messages_processed);
                cJSON_AddNumberToObject(result, "bytes_read",
                                        (double)kstats.bytes_read);
                cJSON_AddNumberToObject(result, "bytes_written",
                                        (double)kstats.bytes_written);
                cJSON_AddNumberToObject(result, "netfilter_packets",
                                        (double)kstats.netfilter_packets);
                cJSON_AddNumberToObject(result, "uptime_seconds",
                                        (double)kstats.uptime_seconds);
            } else {
                cJSON_AddBoolToObject(result, "connected", false);
                cJSON_AddStringToObject(result, "error", "ioctl failed");
            }
        } else {
            cJSON_AddBoolToObject(result, "connected", false);
            cJSON_AddStringToObject(result, "error", "not available");
        }
#else
        cJSON_AddBoolToObject(result, "connected", false);
        cJSON_AddStringToObject(result, "error",
                                "kernel module only available on Linux");
#endif
    } else {
        cJSON *err = cJSON_AddObjectToObject(resp, "error");
        cJSON_AddNumberToObject(err, "code", -32601);
        cJSON_AddStringToObject(err, "message", "method not found");
    }

    char *resp_str = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    cJSON_Delete(req);

    return resp_str;
}

/**
 * Handle a single JSON-RPC request on a Unix domain socket client connection.
 */
static void unix_client_handle(int client_fd)
{
    char buf[UNIX_BUF_SIZE];
    kelp_str_t request = kelp_str_new();

    /* Read until newline or EOF. */
    for (;;) {
        ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
        if (n <= 0)
            break;
        buf[n] = '\0';
        kelp_str_append(&request, buf, (size_t)n);
        if (request.len > 0 && request.data[request.len - 1] == '\n')
            break;
        if (request.len > MAX_POST_DATA)
            break;
    }

    if (request.len == 0) {
        kelp_str_free(&request);
        return;
    }

    kelp_str_trim(&request);

    char *resp_str = jsonrpc_dispatch(request.data, request.len);
    kelp_str_free(&request);

    if (resp_str) {
        size_t rlen = strlen(resp_str);
        /* Append newline delimiter. */
        char *sendbuf = malloc(rlen + 2);
        if (sendbuf) {
            memcpy(sendbuf, resp_str, rlen);
            sendbuf[rlen]     = '\n';
            sendbuf[rlen + 1] = '\0';

            ssize_t written = 0;
            ssize_t total = (ssize_t)(rlen + 1);
            while (written < total) {
                ssize_t n = write(client_fd, sendbuf + written,
                                  (size_t)(total - written));
                if (n <= 0)
                    break;
                written += n;
            }
            free(sendbuf);
        }
        free(resp_str);
    }
}

/**
 * Thread function for handling a Unix socket client.
 */
static void *unix_client_thread(void *arg)
{
    int client_fd = (int)(intptr_t)arg;
    unix_client_handle(client_fd);
    close(client_fd);
    return NULL;
}

/* ---- Kernel reader thread ----------------------------------------------- */

#ifdef __linux__
static void *kernel_reader_thread(void *arg)
{
    (void)arg;
    KELP_INFO("kernel reader thread started");

    while (!g_shutdown) {
        size_t len = 0;
        char *msg = kelp_kernel_recv(g_kernel_fd, &len);
        if (!msg) {
            /* EAGAIN or error — brief sleep and retry */
            usleep(10000); /* 10ms */
            continue;
        }

        /* Dispatch and send response */
        char *response = jsonrpc_dispatch(msg, len);
        free(msg);

        if (response) {
            kelp_kernel_send(g_kernel_fd, response, strlen(response));
            free(response);
        }
    }

    KELP_INFO("kernel reader thread exited");
    return NULL;
}
#endif

/* ---- PID file ----------------------------------------------------------- */

static int pidfile_write(const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        KELP_ERROR("cannot create pidfile %s: %s", path, strerror(errno));
        return -1;
    }
    fprintf(f, "%d\n", getpid());
    fclose(f);
    return 0;
}

static void pidfile_remove(const char *path)
{
    if (path[0])
        unlink(path);
}

/* ---- Daemonize ---------------------------------------------------------- */

static int daemonize_process(void)
{
    pid_t pid = fork();
    if (pid < 0) {
        KELP_ERROR("fork(): %s", strerror(errno));
        return -1;
    }
    if (pid > 0)
        _exit(0); /* Parent exits. */

    /* Child: new session. */
    if (setsid() < 0) {
        KELP_ERROR("setsid(): %s", strerror(errno));
        return -1;
    }

    /* Fork again to ensure we cannot acquire a controlling terminal. */
    pid = fork();
    if (pid < 0) {
        KELP_ERROR("fork(): %s", strerror(errno));
        return -1;
    }
    if (pid > 0)
        _exit(0);

    /* Redirect stdin/stdout/stderr to /dev/null. */
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > 2)
            close(devnull);
    }

    /* Change working directory. */
    if (chdir("/") != 0) {
        /* Non-fatal. */
    }

    /* Reset file creation mask. */
    umask(0027);

    return 0;
}

/* ---- Main event loop ---------------------------------------------------- */

static void event_loop(void)
{
    KELP_INFO("entering event loop");

#ifdef __linux__
    /* epoll-based loop. */
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        KELP_ERROR("epoll_create1: %s", strerror(errno));
        return;
    }

    if (g_unix_fd >= 0) {
        struct epoll_event ev = {
            .events = EPOLLIN,
            .data.fd = g_unix_fd
        };
        epoll_ctl(epfd, EPOLL_CTL_ADD, g_unix_fd, &ev);
    }

    while (!g_shutdown) {
        struct epoll_event events[16];
        int nfds = epoll_wait(epfd, events, 16, 500);
        if (nfds < 0) {
            if (errno == EINTR)
                continue;
            KELP_ERROR("epoll_wait: %s", strerror(errno));
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == g_unix_fd) {
                /* Accept new Unix socket connection. */
                struct sockaddr_un peer;
                socklen_t peer_len = sizeof(peer);
                int client = accept(g_unix_fd,
                                    (struct sockaddr *)&peer, &peer_len);
                if (client >= 0) {
                    pthread_t tid;
                    if (pthread_create(&tid, NULL, unix_client_thread,
                                       (void *)(intptr_t)client) == 0) {
                        pthread_detach(tid);
                    } else {
                        close(client);
                    }
                }
            }
        }
    }

    close(epfd);

#elif defined(__APPLE__) || defined(__FreeBSD__)
    /* kqueue-based loop. */
    int kq = kqueue();
    if (kq < 0) {
        KELP_ERROR("kqueue: %s", strerror(errno));
        return;
    }

    if (g_unix_fd >= 0) {
        struct kevent change;
        EV_SET(&change, g_unix_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
        kevent(kq, &change, 1, NULL, 0, NULL);
    }

    while (!g_shutdown) {
        struct timespec timeout = { .tv_sec = 0, .tv_nsec = 500000000 };
        struct kevent events[16];
        int nev = kevent(kq, NULL, 0, events, 16, &timeout);
        if (nev < 0) {
            if (errno == EINTR)
                continue;
            KELP_ERROR("kevent: %s", strerror(errno));
            break;
        }

        for (int i = 0; i < nev; i++) {
            if ((int)events[i].ident == g_unix_fd) {
                struct sockaddr_un peer;
                socklen_t peer_len = sizeof(peer);
                int client = accept(g_unix_fd,
                                    (struct sockaddr *)&peer, &peer_len);
                if (client >= 0) {
                    pthread_t tid;
                    if (pthread_create(&tid, NULL, unix_client_thread,
                                       (void *)(intptr_t)client) == 0) {
                        pthread_detach(tid);
                    } else {
                        close(client);
                    }
                }
            }
        }
    }

    close(kq);

#else
    /* poll-based fallback. */
    struct pollfd pfds[2];
    int npfds = 0;

    if (g_unix_fd >= 0) {
        pfds[npfds].fd = g_unix_fd;
        pfds[npfds].events = POLLIN;
        npfds++;
    }

    while (!g_shutdown) {
        int ret = poll(pfds, (nfds_t)npfds, 500);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            KELP_ERROR("poll: %s", strerror(errno));
            break;
        }

        for (int i = 0; i < npfds; i++) {
            if (pfds[i].revents & POLLIN && pfds[i].fd == g_unix_fd) {
                struct sockaddr_un peer;
                socklen_t peer_len = sizeof(peer);
                int client = accept(g_unix_fd,
                                    (struct sockaddr *)&peer, &peer_len);
                if (client >= 0) {
                    pthread_t tid;
                    if (pthread_create(&tid, NULL, unix_client_thread,
                                       (void *)(intptr_t)client) == 0) {
                        pthread_detach(tid);
                    } else {
                        close(client);
                    }
                }
            }
        }
    }
#endif

    KELP_INFO("event loop exited");
}

/* ---- Graceful shutdown -------------------------------------------------- */

static void shutdown_gateway(void)
{
    KELP_INFO("shutting down gateway");

#ifdef __linux__
    /* Stop kernel reader thread. */
    if (g_kernel_thread_running) {
        pthread_join(g_kernel_thread, NULL);
        g_kernel_thread_running = false;
    }
    if (g_kernel_fd >= 0) {
        kelp_kernel_close(g_kernel_fd);
        g_kernel_fd = -1;
    }
#endif

    /* Stop HTTP server. */
    if (g_httpd) {
        MHD_stop_daemon(g_httpd);
        g_httpd = NULL;
    }

    /* Close Unix socket. */
    if (g_unix_fd >= 0) {
        close(g_unix_fd);
        g_unix_fd = -1;
    }

    /* Remove socket file. */
    if (g_socket_path) {
        unlink(g_socket_path);
    }

    /* Remove PID file. */
    pidfile_remove(g_pidfile);

#ifdef HAVE_AGENTS
    /* Free global provider and tools */
    if (g_tools)    { kelp_tool_ctx_free(g_tools);   g_tools = NULL; }
    if (g_provider) { kelp_provider_free(g_provider); g_provider = NULL; }
#endif

    /* Shutdown audit. */
    kelp_audit_shutdown();

    KELP_INFO("gateway shutdown complete");
}

/* ---- Usage -------------------------------------------------------------- */

static void usage(void)
{
    printf(
        "Usage: kelp-gateway [options]\n"
        "\n"
        "Options:\n"
        "  -c, --config <path>   Configuration file path\n"
        "  -l, --listen <addr>   Listen address (default: 127.0.0.1)\n"
        "  -p, --port <port>     Listen port (default: 3000)\n"
        "  -s, --socket <path>   Unix socket path\n"
        "  -d, --daemon          Run as daemon\n"
        "  -h, --help            Show this help\n"
        "\n"
        "HTTP API routes:\n"
        "  POST /v1/chat/completions   OpenAI-compatible chat API\n"
        "  POST /v1/messages           Anthropic-compatible messages API\n"
        "  GET  /v1/health             Health check\n"
        "  GET  /v1/config             Current configuration\n"
        "  POST /v1/agent/chat         Agent chat (with tool use)\n"
        "  GET  /v1/sessions           List active sessions\n"
        "\n"
        "JSON-RPC methods (Unix socket / kernel channel):\n"
        "  chat.send       Send a chat message\n"
        "  health          Health check\n"
        "  config.get      Get a configuration value\n"
        "  sessions.list   List active sessions\n"
        "  kernel.status   Kernel module statistics (Linux only)\n"
        "\n"
        "Kernel channel:\n"
        "  On Linux, if the kelp kernel module is loaded, the gateway\n"
        "  connects to /dev/kelp for IPC via a dedicated reader thread.\n"
        "\n"
    );
}

/* ---- Main --------------------------------------------------------------- */

int main(int argc, char **argv)
{
    const char *config_path = NULL;

    static struct option long_options[] = {
        {"config",  required_argument, NULL, 'c'},
        {"listen",  required_argument, NULL, 'l'},
        {"port",    required_argument, NULL, 'p'},
        {"socket",  required_argument, NULL, 's'},
        {"daemon",  no_argument,       NULL, 'd'},
        {"help",    no_argument,       NULL, 'h'},
        {NULL,      0,                 NULL,  0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "c:l:p:s:dh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'c':
            config_path = optarg;
            break;
        case 'l':
            g_listen_addr = optarg;
            break;
        case 'p':
            g_port = atoi(optarg);
            if (g_port <= 0 || g_port > 65535) {
                fprintf(stderr, "kelp-gateway: invalid port: %s\n", optarg);
                return 1;
            }
            break;
        case 's':
            free(g_socket_path);
            g_socket_path = strdup(optarg);
            break;
        case 'd':
            g_daemonize = true;
            break;
        case 'h':
            usage();
            return 0;
        default:
            fprintf(stderr, "Try 'kelp-gateway --help' for more information.\n");
            return 1;
        }
    }

    /* Load configuration. */
    if (config_path) {
        if (kelp_config_load(config_path, &g_cfg) != 0) {
            fprintf(stderr, "kelp-gateway: failed to load config: %s\n",
                    config_path);
            return 1;
        }
    } else {
        kelp_config_load_default(&g_cfg);
    }
    kelp_config_merge_env(&g_cfg);

    /* Apply config defaults if not overridden by CLI. */
    if (g_cfg.gateway.host && strcmp(g_listen_addr, "127.0.0.1") == 0)
        g_listen_addr = g_cfg.gateway.host;
    if (g_cfg.gateway.port > 0 && g_port == 3000)
        g_port = g_cfg.gateway.port;

    /* Determine socket path. */
    if (!g_socket_path) {
        if (g_cfg.gateway.socket_path) {
            g_socket_path = strdup(g_cfg.gateway.socket_path);
        } else {
            g_socket_path = kelp_paths_socket();
        }
    }

    /* WebSocket port: HTTP port + 1. */
    g_ws_port = g_port + 1;

    /* Initialize logging. */
    int log_level = g_cfg.logging.level >= 0 ? g_cfg.logging.level : KELP_LOG_INFO;
    kelp_log_init("kelp-gateway", log_level);

    if (g_cfg.logging.file) {
        FILE *logfp = fopen(g_cfg.logging.file, "a");
        if (logfp)
            kelp_log_set_file(logfp);
        else
            KELP_WARN("cannot open log file %s: %s",
                       g_cfg.logging.file, strerror(errno));
    }

    /* Initialize HTTP subsystem (curl). */
    kelp_http_init();

    /* Initialize audit logging. */
    {
        char *data_dir = kelp_paths_data_dir();
        if (data_dir) {
            char audit_path[512];
            snprintf(audit_path, sizeof(audit_path), "%s/audit.jsonl", data_dir);
            kelp_audit_init(audit_path);
            free(data_dir);
        }
    }

    /* Ensure directories exist. */
    kelp_paths_ensure_dirs();

    /* Daemonize if requested. */
    if (g_daemonize) {
        if (daemonize_process() != 0) {
            fprintf(stderr, "kelp-gateway: failed to daemonize\n");
            return 1;
        }
    }

    /* Write PID file. */
    {
        char *runtime_dir = kelp_paths_runtime_dir();
        if (runtime_dir) {
            snprintf(g_pidfile, sizeof(g_pidfile),
                     "%s/kelp-gateway.pid", runtime_dir);
            pidfile_write(g_pidfile);
            free(runtime_dir);
        }
    }

    /* Install signal handlers. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    /* Use the signal bridge for SIGTERM/SIGINT. */
    kelp_signal_ctx_t *sig_ctx = kelp_signal_ctx_new();
    if (sig_ctx) {
        kelp_signal_watch(sig_ctx, SIGTERM, on_shutdown_signal, NULL);
        kelp_signal_watch(sig_ctx, SIGINT, on_shutdown_signal, NULL);
    } else {
        /* Fallback: direct signal handlers. */
        sa.sa_handler = (void (*)(int))on_shutdown_signal;
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGINT, &sa, NULL);
    }

    /* Record start time for uptime tracking. */
    g_start_time = time(NULL);

    KELP_INFO("kelp-gateway %s starting", KELP_GATEWAY_VERSION);
    KELP_INFO("HTTP: %s:%d", g_listen_addr, g_port);
    KELP_INFO("Unix socket: %s", g_socket_path ? g_socket_path : "(none)");

#ifdef HAVE_AGENTS
    /* Initialize global provider and tools */
    {
        kelp_provider_type_t ptype = resolve_provider_type(
            g_cfg.model.default_provider);
        g_provider = kelp_provider_new(ptype, g_cfg.model.api_key);
        if (g_provider) {
            KELP_INFO("provider initialized: %s",
                       g_cfg.model.default_provider
                           ? g_cfg.model.default_provider : "anthropic");
        } else {
            KELP_WARN("failed to initialize provider (API key set?)");
        }
        g_tools = kelp_tool_ctx_new("/tmp/kelp-workspace");
        if (g_tools) {
            kelp_tool_register_defaults(g_tools);
            KELP_INFO("tools initialized");
        }
    }
#endif

    /* Start HTTP server (libmicrohttpd). */
    unsigned int mhd_flags = MHD_USE_AUTO_INTERNAL_THREAD | MHD_USE_ERROR_LOG;

    g_httpd = MHD_start_daemon(
        mhd_flags,
        (uint16_t)g_port,
        NULL, NULL,                       /* accept policy */
        http_handler, NULL,               /* request handler */
        MHD_OPTION_NOTIFY_COMPLETED, http_completed, NULL,
        MHD_OPTION_THREAD_POOL_SIZE, (unsigned int)THREAD_POOL_SIZE,
        MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)120,
        MHD_OPTION_END);

    if (!g_httpd) {
        KELP_FATAL("failed to start HTTP server on %s:%d", g_listen_addr, g_port);
        shutdown_gateway();
        kelp_config_free(&g_cfg);
        return 1;
    }

    KELP_INFO("HTTP server started on %s:%d with %d threads",
               g_listen_addr, g_port, THREAD_POOL_SIZE);

    /* Create Unix domain socket. */
    if (g_socket_path) {
        g_unix_fd = unix_socket_create(g_socket_path);
        if (g_unix_fd < 0) {
            KELP_WARN("failed to create Unix socket at %s", g_socket_path);
            /* Non-fatal: HTTP still works. */
        }
    }

    /* Open kernel device if available (Linux only). */
#ifdef __linux__
    if (kelp_kernel_available()) {
        g_kernel_fd = kelp_kernel_open();
        if (g_kernel_fd >= 0) {
            if (pthread_create(&g_kernel_thread, NULL,
                               kernel_reader_thread, NULL) == 0) {
                g_kernel_thread_running = true;
                KELP_INFO("kernel channel connected (/dev/kelp)");
            } else {
                KELP_WARN("failed to create kernel reader thread");
                kelp_kernel_close(g_kernel_fd);
                g_kernel_fd = -1;
            }
        } else {
            KELP_WARN("kernel module loaded but /dev/kelp not accessible");
        }
    } else {
        KELP_INFO("kernel module not loaded, skipping /dev/kelp");
    }
#endif

    /* Notify systemd that we are ready. */
#ifdef HAVE_SYSTEMD
    {
        char notify_msg[256];
        snprintf(notify_msg, sizeof(notify_msg),
                 "READY=1\nSTATUS=Gateway running\nMAINPID=%lu",
                 (unsigned long)getpid());
        sd_notify(0, notify_msg);
    }
#endif

    if (!g_daemonize) {
        fprintf(stdout, "kelp-gateway %s running on http://%s:%d\n",
                KELP_GATEWAY_VERSION, g_listen_addr, g_port);
        if (g_socket_path)
            fprintf(stdout, "Unix socket: %s\n", g_socket_path);
        fprintf(stdout, "Press Ctrl-C to stop.\n");
        fflush(stdout);
    }

    /* Main event loop. */
    event_loop();

    /* Graceful shutdown. */
#ifdef HAVE_SYSTEMD
    sd_notify(0, "STOPPING=1\nSTATUS=Shutting down");
#endif

    shutdown_gateway();
    kelp_signal_ctx_free(sig_ctx);
    kelp_config_free(&g_cfg);
    free(g_socket_path);

    KELP_INFO("kelp-gateway exited cleanly");
    return 0;
}
