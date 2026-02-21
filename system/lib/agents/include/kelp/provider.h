/*
 * kelp-linux :: libkelp-agents
 * provider.h - Model provider interface (Anthropic, OpenAI, Google, Ollama, Bedrock)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_PROVIDER_H
#define KELP_PROVIDER_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Provider types ----------------------------------------------------- */

typedef enum {
    KELP_PROVIDER_ANTHROPIC,
    KELP_PROVIDER_OPENAI,
    KELP_PROVIDER_GOOGLE,
    KELP_PROVIDER_OLLAMA,
    KELP_PROVIDER_BEDROCK
} kelp_provider_type_t;

/* ---- Message types ------------------------------------------------------ */

typedef enum {
    KELP_ROLE_SYSTEM,
    KELP_ROLE_USER,
    KELP_ROLE_ASSISTANT,
    KELP_ROLE_TOOL
} kelp_role_t;

/**
 * Chat message.
 *
 * Messages form a singly-linked list representing the conversation history.
 * For KELP_ROLE_TOOL messages, tool_call_id identifies which tool call this
 * result is for.  For KELP_ROLE_ASSISTANT messages with tool calls,
 * tool_name and tool_args describe the requested tool invocation.
 */
typedef struct kelp_message {
    kelp_role_t          role;
    char                 *content;
    char                 *tool_call_id;    /* for tool results */
    char                 *tool_name;       /* for tool calls */
    char                 *tool_args;       /* JSON string of tool arguments */
    struct kelp_message *next;
} kelp_message_t;

/* ---- Streaming ---------------------------------------------------------- */

/**
 * Streaming event delivered via callback.
 *
 * type is one of: "text", "tool_use", "done", "error".
 */
typedef struct kelp_stream_event {
    const char *type;        /* "text", "tool_use", "done", "error" */
    const char *text;        /* for text events */
    const char *tool_name;   /* for tool_use events */
    const char *tool_id;     /* tool call ID */
    const char *tool_args;   /* partial JSON for tool args */
} kelp_stream_event_t;

/**
 * Streaming callback.
 *
 * @param event     The current stream event.
 * @param userdata  Opaque pointer supplied at request time.
 * @return 0 to continue streaming, non-zero to abort.
 */
typedef int (*kelp_stream_cb)(const kelp_stream_event_t *event, void *userdata);

/* ---- Completion options ------------------------------------------------- */

typedef struct kelp_completion_opts {
    const char      *model;
    kelp_message_t *messages;
    const char      *system_prompt;
    int              max_tokens;
    float            temperature;
    const char      *tools_json;      /* JSON array of tool definitions */
    bool             stream;
    kelp_stream_cb  stream_cb;
    void            *stream_userdata;
} kelp_completion_opts_t;

/* ---- Completion result -------------------------------------------------- */

typedef struct kelp_completion {
    char            *content;         /* assistant text response */
    kelp_message_t *tool_calls;      /* linked list of tool call messages */
    int              input_tokens;
    int              output_tokens;
    char            *stop_reason;     /* "end_turn", "tool_use", "max_tokens" */
    char            *model;
    char            *id;
} kelp_completion_t;

/* ---- Provider interface ------------------------------------------------- */

typedef struct kelp_provider {
    kelp_provider_type_t type;
    char *api_key;
    char *base_url;
    char *org_id;
    void *ctx;                        /* provider-specific context */

    /* vtable */
    int  (*complete)(struct kelp_provider *p,
                     const kelp_completion_opts_t *opts,
                     kelp_completion_t *result);
    void (*free_ctx)(void *ctx);
} kelp_provider_t;

/* ---- API ---------------------------------------------------------------- */

/**
 * Create a new provider instance.
 *
 * @param type     Provider type.
 * @param api_key  API key (copied internally; may be NULL for local providers).
 * @return Provider handle, or NULL on allocation failure.
 */
kelp_provider_t *kelp_provider_new(kelp_provider_type_t type, const char *api_key);

/**
 * Free a provider and all owned resources.
 *
 * @param p  Provider handle (may be NULL).
 */
void kelp_provider_free(kelp_provider_t *p);

/**
 * Execute a completion request.
 *
 * @param p       Provider handle.
 * @param opts    Completion options.
 * @param result  Output: populated on success.
 * @return 0 on success, -1 on error.
 */
int kelp_provider_complete(kelp_provider_t *p,
                            const kelp_completion_opts_t *opts,
                            kelp_completion_t *result);

/**
 * Free all dynamically allocated fields in a completion result.
 *
 * @param c  Completion result (may be NULL).
 */
void kelp_completion_free(kelp_completion_t *c);

/**
 * Create a new message.
 *
 * @param role     Message role.
 * @param content  Message content (copied internally; may be NULL).
 * @return Message, or NULL on allocation failure.
 */
kelp_message_t *kelp_message_new(kelp_role_t role, const char *content);

/**
 * Free an entire linked list of messages.
 *
 * @param msg  Head of the list (may be NULL).
 */
void kelp_message_free(kelp_message_t *msg);

/**
 * Append a message to the end of a linked list.
 *
 * @param list  Pointer to the list head pointer.
 * @param msg   Message to append.
 */
void kelp_message_append(kelp_message_t **list, kelp_message_t *msg);

#ifdef __cplusplus
}
#endif

#endif /* KELP_PROVIDER_H */
