/*
 * clawd-linux :: libclawd-agents
 * provider.c - Provider creation, message management, completion dispatch
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/provider.h>
#include <clawd/log.h>
#include <clawd/err.h>

#include <stdlib.h>
#include <string.h>

/* ---- Provider init functions (defined in providers/*.c) ----------------- */

extern int clawd_provider_anthropic_init(clawd_provider_t *p);
extern int clawd_provider_openai_init(clawd_provider_t *p);
extern int clawd_provider_ollama_init(clawd_provider_t *p);
extern int clawd_provider_google_init(clawd_provider_t *p);
extern int clawd_provider_bedrock_init(clawd_provider_t *p);

/* ---- Provider lifecycle ------------------------------------------------- */

clawd_provider_t *clawd_provider_new(clawd_provider_type_t type, const char *api_key)
{
    clawd_provider_t *p = (clawd_provider_t *)calloc(1, sizeof(*p));
    if (!p) return NULL;

    p->type = type;
    if (api_key) {
        p->api_key = strdup(api_key);
        if (!p->api_key) {
            free(p);
            return NULL;
        }
    }

    int rc = 0;
    switch (type) {
    case CLAWD_PROVIDER_ANTHROPIC:
        rc = clawd_provider_anthropic_init(p);
        break;
    case CLAWD_PROVIDER_OPENAI:
        rc = clawd_provider_openai_init(p);
        break;
    case CLAWD_PROVIDER_OLLAMA:
        rc = clawd_provider_ollama_init(p);
        break;
    case CLAWD_PROVIDER_GOOGLE:
        rc = clawd_provider_google_init(p);
        break;
    case CLAWD_PROVIDER_BEDROCK:
        rc = clawd_provider_bedrock_init(p);
        break;
    default:
        CLAWD_ERROR("provider: unknown type %d", (int)type);
        rc = -1;
        break;
    }

    if (rc != 0) {
        clawd_provider_free(p);
        return NULL;
    }

    return p;
}

void clawd_provider_free(clawd_provider_t *p)
{
    if (!p) return;

    if (p->free_ctx && p->ctx) {
        p->free_ctx(p->ctx);
    }

    free(p->api_key);
    free(p->base_url);
    free(p->org_id);
    free(p);
}

int clawd_provider_complete(clawd_provider_t *p,
                            const clawd_completion_opts_t *opts,
                            clawd_completion_t *result)
{
    if (!p || !opts || !result) return -1;

    if (!p->complete) {
        CLAWD_ERROR("provider: complete function not set");
        return -1;
    }

    return p->complete(p, opts, result);
}

/* ---- Completion result -------------------------------------------------- */

void clawd_completion_free(clawd_completion_t *c)
{
    if (!c) return;

    free(c->content);
    c->content = NULL;

    clawd_message_free(c->tool_calls);
    c->tool_calls = NULL;

    free(c->stop_reason);
    c->stop_reason = NULL;

    free(c->model);
    c->model = NULL;

    free(c->id);
    c->id = NULL;

    c->input_tokens  = 0;
    c->output_tokens = 0;
}

/* ---- Message management ------------------------------------------------- */

clawd_message_t *clawd_message_new(clawd_role_t role, const char *content)
{
    clawd_message_t *msg = (clawd_message_t *)calloc(1, sizeof(*msg));
    if (!msg) return NULL;

    msg->role = role;
    if (content) {
        msg->content = strdup(content);
        if (!msg->content) {
            free(msg);
            return NULL;
        }
    }

    return msg;
}

void clawd_message_free(clawd_message_t *msg)
{
    while (msg) {
        clawd_message_t *next = msg->next;
        free(msg->content);
        free(msg->tool_call_id);
        free(msg->tool_name);
        free(msg->tool_args);
        free(msg);
        msg = next;
    }
}

void clawd_message_append(clawd_message_t **list, clawd_message_t *msg)
{
    if (!list || !msg) return;

    msg->next = NULL;

    if (!*list) {
        *list = msg;
        return;
    }

    clawd_message_t *tail = *list;
    while (tail->next) {
        tail = tail->next;
    }
    tail->next = msg;
}
