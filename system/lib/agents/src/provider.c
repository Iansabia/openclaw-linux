/*
 * kelp-linux :: libkelp-agents
 * provider.c - Provider creation, message management, completion dispatch
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/provider.h>
#include <kelp/log.h>
#include <kelp/err.h>

#include <stdlib.h>
#include <string.h>

/* ---- Provider init functions (defined in providers/*.c) ----------------- */

extern int kelp_provider_anthropic_init(kelp_provider_t *p);
extern int kelp_provider_openai_init(kelp_provider_t *p);
extern int kelp_provider_ollama_init(kelp_provider_t *p);
extern int kelp_provider_google_init(kelp_provider_t *p);
extern int kelp_provider_bedrock_init(kelp_provider_t *p);

/* ---- Provider lifecycle ------------------------------------------------- */

kelp_provider_t *kelp_provider_new(kelp_provider_type_t type, const char *api_key)
{
    kelp_provider_t *p = (kelp_provider_t *)calloc(1, sizeof(*p));
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
    case KELP_PROVIDER_ANTHROPIC:
        rc = kelp_provider_anthropic_init(p);
        break;
    case KELP_PROVIDER_OPENAI:
        rc = kelp_provider_openai_init(p);
        break;
    case KELP_PROVIDER_OLLAMA:
        rc = kelp_provider_ollama_init(p);
        break;
    case KELP_PROVIDER_GOOGLE:
        rc = kelp_provider_google_init(p);
        break;
    case KELP_PROVIDER_BEDROCK:
        rc = kelp_provider_bedrock_init(p);
        break;
    default:
        KELP_ERROR("provider: unknown type %d", (int)type);
        rc = -1;
        break;
    }

    if (rc != 0) {
        kelp_provider_free(p);
        return NULL;
    }

    return p;
}

void kelp_provider_free(kelp_provider_t *p)
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

int kelp_provider_complete(kelp_provider_t *p,
                            const kelp_completion_opts_t *opts,
                            kelp_completion_t *result)
{
    if (!p || !opts || !result) return -1;

    if (!p->complete) {
        KELP_ERROR("provider: complete function not set");
        return -1;
    }

    return p->complete(p, opts, result);
}

/* ---- Completion result -------------------------------------------------- */

void kelp_completion_free(kelp_completion_t *c)
{
    if (!c) return;

    free(c->content);
    c->content = NULL;

    kelp_message_free(c->tool_calls);
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

kelp_message_t *kelp_message_new(kelp_role_t role, const char *content)
{
    kelp_message_t *msg = (kelp_message_t *)calloc(1, sizeof(*msg));
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

void kelp_message_free(kelp_message_t *msg)
{
    while (msg) {
        kelp_message_t *next = msg->next;
        free(msg->content);
        free(msg->tool_call_id);
        free(msg->tool_name);
        free(msg->tool_args);
        free(msg);
        msg = next;
    }
}

void kelp_message_append(kelp_message_t **list, kelp_message_t *msg)
{
    if (!list || !msg) return;

    msg->next = NULL;

    if (!*list) {
        *list = msg;
        return;
    }

    kelp_message_t *tail = *list;
    while (tail->next) {
        tail = tail->next;
    }
    tail->next = msg;
}
