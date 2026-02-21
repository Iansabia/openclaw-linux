/*
 * kelp-linux :: libkelp-agents
 * providers/anthropic.c - Anthropic Claude API provider
 *
 * POST https://api.anthropic.com/v1/messages
 * Headers: x-api-key, anthropic-version: 2023-06-01, content-type: application/json
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/provider.h>
#include <kelp/http.h>
#include <kelp/json.h>
#include <kelp/str.h>
#include <kelp/log.h>
#include <kelp/err.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define ANTHROPIC_API_URL    "https://api.anthropic.com/v1/messages"
#define ANTHROPIC_VERSION    "2023-06-01"
#define DEFAULT_MODEL        "claude-sonnet-4-20250514"
#define DEFAULT_MAX_TOKENS   4096

/* ---- Forward declarations ----------------------------------------------- */

static int anthropic_complete(kelp_provider_t *p,
                              const kelp_completion_opts_t *opts,
                              kelp_completion_t *result);

/* ---- Initialization ----------------------------------------------------- */

int kelp_provider_anthropic_init(kelp_provider_t *p)
{
    if (!p) return -1;
    p->complete = anthropic_complete;
    if (!p->base_url) {
        p->base_url = strdup(ANTHROPIC_API_URL);
    }
    return 0;
}

/* ---- JSON construction helpers ------------------------------------------ */

static const char *role_to_string(kelp_role_t role)
{
    switch (role) {
    case KELP_ROLE_USER:      return "user";
    case KELP_ROLE_ASSISTANT: return "assistant";
    case KELP_ROLE_TOOL:      return "user";  /* tool results sent as user in Anthropic */
    case KELP_ROLE_SYSTEM:    return "user";   /* system handled separately */
    }
    return "user";
}

/*
 * Build the JSON request body for the Anthropic Messages API.
 *
 * {
 *   "model": "...",
 *   "max_tokens": ...,
 *   "system": "...",
 *   "messages": [...],
 *   "tools": [...],
 *   "temperature": ...,
 *   "stream": false
 * }
 */
static char *build_request_json(const kelp_provider_t *p,
                                 const kelp_completion_opts_t *opts)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    const char *model = opts->model ? opts->model : DEFAULT_MODEL;
    cJSON_AddStringToObject(root, "model", model);

    int max_tokens = opts->max_tokens > 0 ? opts->max_tokens : DEFAULT_MAX_TOKENS;
    cJSON_AddNumberToObject(root, "max_tokens", max_tokens);

    if (opts->system_prompt) {
        cJSON_AddStringToObject(root, "system", opts->system_prompt);
    }

    if (opts->temperature >= 0.0f) {
        cJSON_AddNumberToObject(root, "temperature", (double)opts->temperature);
    }

    if (opts->stream) {
        cJSON_AddBoolToObject(root, "stream", 1);
    }

    /* Build messages array */
    cJSON *messages = cJSON_CreateArray();
    if (!messages) {
        cJSON_Delete(root);
        return NULL;
    }

    for (kelp_message_t *msg = opts->messages; msg; msg = msg->next) {
        if (msg->role == KELP_ROLE_SYSTEM) continue;  /* handled via system field */

        cJSON *jmsg = cJSON_CreateObject();
        if (!jmsg) continue;

        if (msg->role == KELP_ROLE_TOOL && msg->tool_call_id) {
            /* Tool result: wrap as user message with tool_result content block */
            cJSON_AddStringToObject(jmsg, "role", "user");
            cJSON *content = cJSON_CreateArray();
            cJSON *block = cJSON_CreateObject();
            cJSON_AddStringToObject(block, "type", "tool_result");
            cJSON_AddStringToObject(block, "tool_use_id", msg->tool_call_id);
            if (msg->content) {
                cJSON_AddStringToObject(block, "content", msg->content);
            }
            cJSON_AddItemToArray(content, block);
            cJSON_AddItemToObject(jmsg, "content", content);
        } else if (msg->role == KELP_ROLE_ASSISTANT && msg->tool_name) {
            /* Assistant message with tool_use */
            cJSON_AddStringToObject(jmsg, "role", "assistant");
            cJSON *content = cJSON_CreateArray();

            /* If there's text content, add it first */
            if (msg->content && *msg->content) {
                cJSON *text_block = cJSON_CreateObject();
                cJSON_AddStringToObject(text_block, "type", "text");
                cJSON_AddStringToObject(text_block, "text", msg->content);
                cJSON_AddItemToArray(content, text_block);
            }

            /* Add tool_use block */
            cJSON *tool_block = cJSON_CreateObject();
            cJSON_AddStringToObject(tool_block, "type", "tool_use");
            cJSON_AddStringToObject(tool_block, "id", msg->tool_call_id ? msg->tool_call_id : "");
            cJSON_AddStringToObject(tool_block, "name", msg->tool_name);
            if (msg->tool_args) {
                cJSON *args = cJSON_Parse(msg->tool_args);
                if (args) {
                    cJSON_AddItemToObject(tool_block, "input", args);
                } else {
                    cJSON_AddItemToObject(tool_block, "input", cJSON_CreateObject());
                }
            } else {
                cJSON_AddItemToObject(tool_block, "input", cJSON_CreateObject());
            }
            cJSON_AddItemToArray(content, tool_block);
            cJSON_AddItemToObject(jmsg, "content", content);
        } else {
            /* Regular text message */
            cJSON_AddStringToObject(jmsg, "role", role_to_string(msg->role));
            if (msg->content) {
                cJSON_AddStringToObject(jmsg, "content", msg->content);
            }
        }

        cJSON_AddItemToArray(messages, jmsg);
    }

    cJSON_AddItemToObject(root, "messages", messages);

    /* Tools array */
    if (opts->tools_json) {
        cJSON *tools = cJSON_Parse(opts->tools_json);
        if (tools && cJSON_IsArray(tools)) {
            cJSON_AddItemToObject(root, "tools", tools);
        } else {
            if (tools) cJSON_Delete(tools);
        }
    }

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json_str;
}

/* ---- Response parsing --------------------------------------------------- */

/*
 * Parse the Anthropic API response JSON:
 * {
 *   "id": "msg_...",
 *   "type": "message",
 *   "role": "assistant",
 *   "content": [
 *     {"type": "text", "text": "..."},
 *     {"type": "tool_use", "id": "...", "name": "...", "input": {...}}
 *   ],
 *   "model": "...",
 *   "stop_reason": "end_turn" | "tool_use" | "max_tokens",
 *   "usage": {"input_tokens": N, "output_tokens": N}
 * }
 */
static int parse_response(const char *body, kelp_completion_t *result)
{
    if (!body || !result) return -1;

    cJSON *root = cJSON_Parse(body);
    if (!root) {
        KELP_ERROR("anthropic: failed to parse response JSON");
        return -1;
    }

    /* Check for error response */
    cJSON *error_obj = cJSON_GetObjectItem(root, "error");
    if (error_obj) {
        const char *emsg = kelp_json_get_string(error_obj, "message");
        KELP_ERROR("anthropic API error: %s", emsg ? emsg : "unknown");
        cJSON_Delete(root);
        return -1;
    }

    /* ID and model */
    const char *id = kelp_json_get_string(root, "id");
    if (id) result->id = strdup(id);

    const char *model = kelp_json_get_string(root, "model");
    if (model) result->model = strdup(model);

    /* Stop reason */
    const char *stop = kelp_json_get_string(root, "stop_reason");
    if (stop) result->stop_reason = strdup(stop);

    /* Usage */
    cJSON *usage = cJSON_GetObjectItem(root, "usage");
    if (usage) {
        result->input_tokens  = kelp_json_get_int(usage, "input_tokens", 0);
        result->output_tokens = kelp_json_get_int(usage, "output_tokens", 0);
    }

    /* Content blocks */
    cJSON *content = cJSON_GetObjectItem(root, "content");
    if (content && cJSON_IsArray(content)) {
        kelp_str_t text_buf = kelp_str_new();
        kelp_message_t *tool_calls = NULL;

        cJSON *block;
        cJSON_ArrayForEach(block, content) {
            const char *type = kelp_json_get_string(block, "type");
            if (!type) continue;

            if (strcmp(type, "text") == 0) {
                const char *text = kelp_json_get_string(block, "text");
                if (text) {
                    kelp_str_append_cstr(&text_buf, text);
                }
            } else if (strcmp(type, "tool_use") == 0) {
                const char *tool_id   = kelp_json_get_string(block, "id");
                const char *tool_name = kelp_json_get_string(block, "name");
                cJSON *input = cJSON_GetObjectItem(block, "input");

                kelp_message_t *tc = kelp_message_new(KELP_ROLE_ASSISTANT, NULL);
                if (tc) {
                    if (tool_id)   tc->tool_call_id = strdup(tool_id);
                    if (tool_name) tc->tool_name    = strdup(tool_name);
                    if (input) {
                        char *args_str = cJSON_PrintUnformatted(input);
                        if (args_str) {
                            tc->tool_args = args_str;
                        }
                    }
                    kelp_message_append(&tool_calls, tc);
                }
            }
        }

        if (text_buf.len > 0) {
            result->content = strdup(text_buf.data);
        }
        kelp_str_free(&text_buf);
        result->tool_calls = tool_calls;
    }

    cJSON_Delete(root);
    return 0;
}

/* ---- SSE streaming ------------------------------------------------------ */

typedef struct {
    kelp_stream_cb  cb;
    void            *userdata;
    kelp_str_t      event_buf;
    kelp_completion_t *result;
    kelp_str_t      text_accum;
    kelp_message_t *tool_calls;
    /* Current tool use tracking */
    char            *current_tool_id;
    char            *current_tool_name;
    kelp_str_t      current_tool_args;
} sse_ctx_t;

static int handle_sse_event(const kelp_sse_event_t *event, void *userdata)
{
    sse_ctx_t *ctx = (sse_ctx_t *)userdata;
    if (!event || !event->data) return 0;

    /* Skip [DONE] marker or empty data */
    if (strcmp(event->data, "[DONE]") == 0) {
        if (ctx->cb) {
            kelp_stream_event_t se = {0};
            se.type = "done";
            ctx->cb(&se, ctx->userdata);
        }
        return 0;
    }

    cJSON *json = cJSON_Parse(event->data);
    if (!json) return 0;

    const char *type = kelp_json_get_string(json, "type");
    if (!type) {
        cJSON_Delete(json);
        return 0;
    }

    if (strcmp(type, "content_block_start") == 0) {
        cJSON *content_block = cJSON_GetObjectItem(json, "content_block");
        if (content_block) {
            const char *btype = kelp_json_get_string(content_block, "type");
            if (btype && strcmp(btype, "tool_use") == 0) {
                free(ctx->current_tool_id);
                free(ctx->current_tool_name);
                const char *tid = kelp_json_get_string(content_block, "id");
                const char *tname = kelp_json_get_string(content_block, "name");
                ctx->current_tool_id = tid ? strdup(tid) : NULL;
                ctx->current_tool_name = tname ? strdup(tname) : NULL;
                kelp_str_free(&ctx->current_tool_args);
                ctx->current_tool_args = kelp_str_new();
            }
        }
    } else if (strcmp(type, "content_block_delta") == 0) {
        cJSON *delta = cJSON_GetObjectItem(json, "delta");
        if (delta) {
            const char *dtype = kelp_json_get_string(delta, "type");
            if (dtype && strcmp(dtype, "text_delta") == 0) {
                const char *text = kelp_json_get_string(delta, "text");
                if (text) {
                    kelp_str_append_cstr(&ctx->text_accum, text);
                    if (ctx->cb) {
                        kelp_stream_event_t se = {0};
                        se.type = "text";
                        se.text = text;
                        ctx->cb(&se, ctx->userdata);
                    }
                }
            } else if (dtype && strcmp(dtype, "input_json_delta") == 0) {
                const char *partial = kelp_json_get_string(delta, "partial_json");
                if (partial) {
                    kelp_str_append_cstr(&ctx->current_tool_args, partial);
                    if (ctx->cb) {
                        kelp_stream_event_t se = {0};
                        se.type = "tool_use";
                        se.tool_name = ctx->current_tool_name;
                        se.tool_id   = ctx->current_tool_id;
                        se.tool_args = partial;
                        ctx->cb(&se, ctx->userdata);
                    }
                }
            }
        }
    } else if (strcmp(type, "content_block_stop") == 0) {
        /* If we were accumulating a tool call, finalize it */
        if (ctx->current_tool_name) {
            kelp_message_t *tc = kelp_message_new(KELP_ROLE_ASSISTANT, NULL);
            if (tc) {
                tc->tool_call_id = ctx->current_tool_id;
                tc->tool_name    = ctx->current_tool_name;
                tc->tool_args    = ctx->current_tool_args.data ?
                                   strdup(ctx->current_tool_args.data) : NULL;
                kelp_message_append(&ctx->tool_calls, tc);
            } else {
                free(ctx->current_tool_id);
                free(ctx->current_tool_name);
            }
            ctx->current_tool_id   = NULL;
            ctx->current_tool_name = NULL;
            kelp_str_free(&ctx->current_tool_args);
            ctx->current_tool_args = kelp_str_new();
        }
    } else if (strcmp(type, "message_delta") == 0) {
        cJSON *delta = cJSON_GetObjectItem(json, "delta");
        if (delta) {
            const char *stop = kelp_json_get_string(delta, "stop_reason");
            if (stop && ctx->result) {
                free(ctx->result->stop_reason);
                ctx->result->stop_reason = strdup(stop);
            }
        }
        cJSON *usage = cJSON_GetObjectItem(json, "usage");
        if (usage && ctx->result) {
            ctx->result->output_tokens = kelp_json_get_int(usage, "output_tokens", 0);
        }
    } else if (strcmp(type, "message_start") == 0) {
        cJSON *message = cJSON_GetObjectItem(json, "message");
        if (message && ctx->result) {
            const char *id = kelp_json_get_string(message, "id");
            const char *model = kelp_json_get_string(message, "model");
            if (id)    ctx->result->id    = strdup(id);
            if (model) ctx->result->model = strdup(model);
            cJSON *usage = cJSON_GetObjectItem(message, "usage");
            if (usage) {
                ctx->result->input_tokens = kelp_json_get_int(usage, "input_tokens", 0);
            }
        }
    } else if (strcmp(type, "error") == 0) {
        cJSON *error_obj = cJSON_GetObjectItem(json, "error");
        const char *emsg = error_obj ?
            kelp_json_get_string(error_obj, "message") : "unknown error";
        KELP_ERROR("anthropic stream error: %s", emsg ? emsg : "unknown");
        if (ctx->cb) {
            kelp_stream_event_t se = {0};
            se.type = "error";
            se.text = emsg;
            ctx->cb(&se, ctx->userdata);
        }
    }

    cJSON_Delete(json);
    return 0;
}

/* ---- Main completion ---------------------------------------------------- */

static int anthropic_complete(kelp_provider_t *p,
                              const kelp_completion_opts_t *opts,
                              kelp_completion_t *result)
{
    if (!p || !opts || !result) return -1;

    memset(result, 0, sizeof(*result));

    /* Build request JSON */
    char *body = build_request_json(p, opts);
    if (!body) {
        KELP_ERROR("anthropic: failed to build request JSON");
        return -1;
    }

    /* Set up headers */
    kelp_http_header_t *headers = NULL;
    kelp_http_header_add(&headers, "content-type", "application/json");
    kelp_http_header_add(&headers, "anthropic-version", ANTHROPIC_VERSION);
    if (p->api_key) {
        /* OAuth tokens (sk-ant-oat*) use Bearer auth; regular keys use x-api-key */
        if (strncmp(p->api_key, "sk-ant-oat", 10) == 0) {
            char bearer[8192];
            snprintf(bearer, sizeof(bearer), "Bearer %s", p->api_key);
            kelp_http_header_add(&headers, "Authorization", bearer);
        } else {
            kelp_http_header_add(&headers, "x-api-key", p->api_key);
        }
    }

    const char *url = p->base_url ? p->base_url : ANTHROPIC_API_URL;

    kelp_http_request_t req = {0};
    req.method  = "POST";
    req.url     = url;
    req.headers = headers;
    req.body    = body;
    req.body_len = strlen(body);
    req.timeout_ms = 120000;  /* 2 minute timeout */
    req.follow_redirects = true;

    int rc;

    if (opts->stream && opts->stream_cb) {
        /* Streaming via SSE */
        sse_ctx_t ctx = {0};
        ctx.cb        = opts->stream_cb;
        ctx.userdata  = opts->stream_userdata;
        ctx.result    = result;
        ctx.text_accum = kelp_str_new();
        ctx.current_tool_args = kelp_str_new();

        rc = kelp_http_sse(&req, handle_sse_event, &ctx);

        /* Copy accumulated data to result */
        if (ctx.text_accum.len > 0) {
            result->content = strdup(ctx.text_accum.data);
        }
        result->tool_calls = ctx.tool_calls;

        kelp_str_free(&ctx.text_accum);
        kelp_str_free(&ctx.current_tool_args);
        free(ctx.current_tool_id);
        free(ctx.current_tool_name);
    } else {
        /* Synchronous request */
        kelp_http_response_t resp = {0};
        rc = kelp_http_request(&req, &resp);

        if (rc == 0 && resp.body) {
            /* NUL-terminate body */
            char *resp_body = (char *)malloc(resp.body_len + 1);
            if (resp_body) {
                memcpy(resp_body, resp.body, resp.body_len);
                resp_body[resp.body_len] = '\0';

                if (resp.status_code >= 200 && resp.status_code < 300) {
                    rc = parse_response(resp_body, result);
                } else {
                    KELP_ERROR("anthropic: HTTP %d: %s", resp.status_code, resp_body);
                    rc = -1;
                }
                free(resp_body);
            } else {
                rc = -1;
            }
        } else if (rc != 0) {
            KELP_ERROR("anthropic: HTTP request failed");
        }

        kelp_http_response_free(&resp);
    }

    free(body);
    kelp_http_header_free(headers);
    return rc;
}
