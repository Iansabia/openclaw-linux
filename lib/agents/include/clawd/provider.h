/*
 * clawd-linux :: libclawd-agents
 * provider.h - Model provider interface (Anthropic, OpenAI, Google, Ollama, Bedrock)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_PROVIDER_H
#define CLAWD_PROVIDER_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Provider types ----------------------------------------------------- */

typedef enum {
    CLAWD_PROVIDER_ANTHROPIC,
    CLAWD_PROVIDER_OPENAI,
    CLAWD_PROVIDER_GOOGLE,
    CLAWD_PROVIDER_OLLAMA,
    CLAWD_PROVIDER_BEDROCK
} clawd_provider_type_t;

/* ---- Message types ------------------------------------------------------ */

typedef enum {
    CLAWD_ROLE_SYSTEM,
    CLAWD_ROLE_USER,
    CLAWD_ROLE_ASSISTANT,
    CLAWD_ROLE_TOOL
} clawd_role_t;

/**
 * Chat message.
 *
 * Messages form a singly-linked list representing the conversation history.
 * For CLAWD_ROLE_TOOL messages, tool_call_id identifies which tool call this
 * result is for.  For CLAWD_ROLE_ASSISTANT messages with tool calls,
 * tool_name and tool_args describe the requested tool invocation.
 */
typedef struct clawd_message {
    clawd_role_t          role;
    char                 *content;
    char                 *tool_call_id;    /* for tool results */
    char                 *tool_name;       /* for tool calls */
    char                 *tool_args;       /* JSON string of tool arguments */
    struct clawd_message *next;
} clawd_message_t;

/* ---- Streaming ---------------------------------------------------------- */

/**
 * Streaming event delivered via callback.
 *
 * type is one of: "text", "tool_use", "done", "error".
 */
typedef struct clawd_stream_event {
    const char *type;        /* "text", "tool_use", "done", "error" */
    const char *text;        /* for text events */
    const char *tool_name;   /* for tool_use events */
    const char *tool_id;     /* tool call ID */
    const char *tool_args;   /* partial JSON for tool args */
} clawd_stream_event_t;

/**
 * Streaming callback.
 *
 * @param event     The current stream event.
 * @param userdata  Opaque pointer supplied at request time.
 * @return 0 to continue streaming, non-zero to abort.
 */
typedef int (*clawd_stream_cb)(const clawd_stream_event_t *event, void *userdata);

/* ---- Completion options ------------------------------------------------- */

typedef struct clawd_completion_opts {
    const char      *model;
    clawd_message_t *messages;
    const char      *system_prompt;
    int              max_tokens;
    float            temperature;
    const char      *tools_json;      /* JSON array of tool definitions */
    bool             stream;
    clawd_stream_cb  stream_cb;
    void            *stream_userdata;
} clawd_completion_opts_t;

/* ---- Completion result -------------------------------------------------- */

typedef struct clawd_completion {
    char            *content;         /* assistant text response */
    clawd_message_t *tool_calls;      /* linked list of tool call messages */
    int              input_tokens;
    int              output_tokens;
    char            *stop_reason;     /* "end_turn", "tool_use", "max_tokens" */
    char            *model;
    char            *id;
} clawd_completion_t;

/* ---- Provider interface ------------------------------------------------- */

typedef struct clawd_provider {
    clawd_provider_type_t type;
    char *api_key;
    char *base_url;
    char *org_id;
    void *ctx;                        /* provider-specific context */

    /* vtable */
    int  (*complete)(struct clawd_provider *p,
                     const clawd_completion_opts_t *opts,
                     clawd_completion_t *result);
    void (*free_ctx)(void *ctx);
} clawd_provider_t;

/* ---- API ---------------------------------------------------------------- */

/**
 * Create a new provider instance.
 *
 * @param type     Provider type.
 * @param api_key  API key (copied internally; may be NULL for local providers).
 * @return Provider handle, or NULL on allocation failure.
 */
clawd_provider_t *clawd_provider_new(clawd_provider_type_t type, const char *api_key);

/**
 * Free a provider and all owned resources.
 *
 * @param p  Provider handle (may be NULL).
 */
void clawd_provider_free(clawd_provider_t *p);

/**
 * Execute a completion request.
 *
 * @param p       Provider handle.
 * @param opts    Completion options.
 * @param result  Output: populated on success.
 * @return 0 on success, -1 on error.
 */
int clawd_provider_complete(clawd_provider_t *p,
                            const clawd_completion_opts_t *opts,
                            clawd_completion_t *result);

/**
 * Free all dynamically allocated fields in a completion result.
 *
 * @param c  Completion result (may be NULL).
 */
void clawd_completion_free(clawd_completion_t *c);

/**
 * Create a new message.
 *
 * @param role     Message role.
 * @param content  Message content (copied internally; may be NULL).
 * @return Message, or NULL on allocation failure.
 */
clawd_message_t *clawd_message_new(clawd_role_t role, const char *content);

/**
 * Free an entire linked list of messages.
 *
 * @param msg  Head of the list (may be NULL).
 */
void clawd_message_free(clawd_message_t *msg);

/**
 * Append a message to the end of a linked list.
 *
 * @param list  Pointer to the list head pointer.
 * @param msg   Message to append.
 */
void clawd_message_append(clawd_message_t **list, clawd_message_t *msg);

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_PROVIDER_H */
