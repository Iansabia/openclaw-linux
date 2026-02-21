/*
 * kelp-linux :: libkelp-agents
 * providers/openai.c - OpenAI Chat Completions API provider
 *
 * POST https://api.openai.com/v1/chat/completions
 * Headers: Authorization: Bearer <key>, Content-Type: application/json
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

#define OPENAI_API_URL      "https://api.openai.com/v1/chat/completions"
#define DEFAULT_MODEL       "gpt-4o"
#define DEFAULT_MAX_TOKENS  4096

/* ---- Forward declarations ----------------------------------------------- */

static int openai_complete(kelp_provider_t *p,
                           const kelp_completion_opts_t *opts,
                           kelp_completion_t *result);

/* ---- Initialization ----------------------------------------------------- */

int kelp_provider_openai_init(kelp_provider_t *p)
{
    if (!p) return -1;
    p->complete = openai_complete;
    if (!p->base_url) {
        p->base_url = strdup(OPENAI_API_URL);
    }
    return 0;
}

/* ---- JSON construction -------------------------------------------------- */

static const char *role_to_string(kelp_role_t role)
{
    switch (role) {
    case KELP_ROLE_SYSTEM:    return "system";
    case KELP_ROLE_USER:      return "user";
    case KELP_ROLE_ASSISTANT: return "assistant";
    case KELP_ROLE_TOOL:      return "tool";
    }
    return "user";
}

/*
 * Build the JSON request body for the OpenAI Chat Completions API.
 *
 * {
 *   "model": "...",
 *   "max_tokens": ...,
 *   "messages": [
 *     {"role": "system", "content": "..."},
 *     {"role": "user", "content": "..."},
 *     ...
 *   ],
 *   "tools": [...],
 *   "temperature": ...
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

    /* System prompt as first message */
    if (opts->system_prompt) {
        cJSON *sys = cJSON_CreateObject();
        cJSON_AddStringToObject(sys, "role", "system");
        cJSON_AddStringToObject(sys, "content", opts->system_prompt);
        cJSON_AddItemToArray(messages, sys);
    }

    for (kelp_message_t *msg = opts->messages; msg; msg = msg->next) {
        if (msg->role == KELP_ROLE_SYSTEM) continue;

        cJSON *jmsg = cJSON_CreateObject();
        if (!jmsg) continue;

        if (msg->role == KELP_ROLE_TOOL && msg->tool_call_id) {
            /* Tool result message */
            cJSON_AddStringToObject(jmsg, "role", "tool");
            cJSON_AddStringToObject(jmsg, "tool_call_id", msg->tool_call_id);
            if (msg->content) {
                cJSON_AddStringToObject(jmsg, "content", msg->content);
            }
        } else if (msg->role == KELP_ROLE_ASSISTANT && msg->tool_name) {
            /* Assistant with tool_calls */
            cJSON_AddStringToObject(jmsg, "role", "assistant");
            if (msg->content) {
                cJSON_AddStringToObject(jmsg, "content", msg->content);
            }

            cJSON *tool_calls = cJSON_CreateArray();
            cJSON *tc = cJSON_CreateObject();
            cJSON_AddStringToObject(tc, "id", msg->tool_call_id ? msg->tool_call_id : "");
            cJSON_AddStringToObject(tc, "type", "function");

            cJSON *func = cJSON_CreateObject();
            cJSON_AddStringToObject(func, "name", msg->tool_name);
            cJSON_AddStringToObject(func, "arguments", msg->tool_args ? msg->tool_args : "{}");
            cJSON_AddItemToObject(tc, "function", func);

            cJSON_AddItemToArray(tool_calls, tc);
            cJSON_AddItemToObject(jmsg, "tool_calls", tool_calls);
        } else {
            /* Regular message */
            cJSON_AddStringToObject(jmsg, "role", role_to_string(msg->role));
            if (msg->content) {
                cJSON_AddStringToObject(jmsg, "content", msg->content);
            }
        }

        cJSON_AddItemToArray(messages, jmsg);
    }

    cJSON_AddItemToObject(root, "messages", messages);

    /* Tools: convert from Anthropic format to OpenAI function format */
    if (opts->tools_json) {
        cJSON *tools_in = cJSON_Parse(opts->tools_json);
        if (tools_in && cJSON_IsArray(tools_in)) {
            cJSON *tools_out = cJSON_CreateArray();
            cJSON *tool;
            cJSON_ArrayForEach(tool, tools_in) {
                const char *name = kelp_json_get_string(tool, "name");
                const char *desc = kelp_json_get_string(tool, "description");
                cJSON *input_schema = cJSON_GetObjectItem(tool, "input_schema");

                cJSON *otool = cJSON_CreateObject();
                cJSON_AddStringToObject(otool, "type", "function");

                cJSON *func = cJSON_CreateObject();
                if (name) cJSON_AddStringToObject(func, "name", name);
                if (desc) cJSON_AddStringToObject(func, "description", desc);
                if (input_schema) {
                    cJSON_AddItemToObject(func, "parameters",
                                          cJSON_Duplicate(input_schema, 1));
                }
                cJSON_AddItemToObject(otool, "function", func);
                cJSON_AddItemToArray(tools_out, otool);
            }
            cJSON_AddItemToObject(root, "tools", tools_out);
            cJSON_Delete(tools_in);
        } else {
            if (tools_in) cJSON_Delete(tools_in);
        }
    }

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json_str;
}

/* ---- Response parsing --------------------------------------------------- */

static int parse_response(const char *body, kelp_completion_t *result)
{
    if (!body || !result) return -1;

    cJSON *root = cJSON_Parse(body);
    if (!root) {
        KELP_ERROR("openai: failed to parse response JSON");
        return -1;
    }

    /* Check for error */
    cJSON *error_obj = cJSON_GetObjectItem(root, "error");
    if (error_obj) {
        const char *emsg = kelp_json_get_string(error_obj, "message");
        KELP_ERROR("openai API error: %s", emsg ? emsg : "unknown");
        cJSON_Delete(root);
        return -1;
    }

    /* ID and model */
    const char *id = kelp_json_get_string(root, "id");
    if (id) result->id = strdup(id);

    const char *model = kelp_json_get_string(root, "model");
    if (model) result->model = strdup(model);

    /* Usage */
    cJSON *usage = cJSON_GetObjectItem(root, "usage");
    if (usage) {
        result->input_tokens  = kelp_json_get_int(usage, "prompt_tokens", 0);
        result->output_tokens = kelp_json_get_int(usage, "completion_tokens", 0);
    }

    /* Choices */
    cJSON *choices = cJSON_GetObjectItem(root, "choices");
    if (choices && cJSON_IsArray(choices)) {
        cJSON *choice = cJSON_GetArrayItem(choices, 0);
        if (choice) {
            /* finish_reason -> stop_reason */
            const char *finish = kelp_json_get_string(choice, "finish_reason");
            if (finish) {
                if (strcmp(finish, "stop") == 0) {
                    result->stop_reason = strdup("end_turn");
                } else if (strcmp(finish, "tool_calls") == 0) {
                    result->stop_reason = strdup("tool_use");
                } else if (strcmp(finish, "length") == 0) {
                    result->stop_reason = strdup("max_tokens");
                } else {
                    result->stop_reason = strdup(finish);
                }
            }

            cJSON *message = cJSON_GetObjectItem(choice, "message");
            if (message) {
                const char *content = kelp_json_get_string(message, "content");
                if (content) {
                    result->content = strdup(content);
                }

                /* Tool calls */
                cJSON *tool_calls = cJSON_GetObjectItem(message, "tool_calls");
                if (tool_calls && cJSON_IsArray(tool_calls)) {
                    cJSON *tc;
                    cJSON_ArrayForEach(tc, tool_calls) {
                        const char *tc_id = kelp_json_get_string(tc, "id");
                        cJSON *func = cJSON_GetObjectItem(tc, "function");
                        if (!func) continue;

                        const char *fname = kelp_json_get_string(func, "name");
                        const char *fargs = kelp_json_get_string(func, "arguments");

                        kelp_message_t *msg = kelp_message_new(KELP_ROLE_ASSISTANT, NULL);
                        if (msg) {
                            if (tc_id) msg->tool_call_id = strdup(tc_id);
                            if (fname) msg->tool_name    = strdup(fname);
                            if (fargs) msg->tool_args    = strdup(fargs);
                            kelp_message_append(&result->tool_calls, msg);
                        }
                    }
                }
            }
        }
    }

    cJSON_Delete(root);
    return 0;
}

/* ---- Main completion ---------------------------------------------------- */

static int openai_complete(kelp_provider_t *p,
                           const kelp_completion_opts_t *opts,
                           kelp_completion_t *result)
{
    if (!p || !opts || !result) return -1;

    memset(result, 0, sizeof(*result));

    char *body = build_request_json(p, opts);
    if (!body) {
        KELP_ERROR("openai: failed to build request JSON");
        return -1;
    }

    /* Build Authorization header */
    kelp_str_t auth_val = kelp_str_new();
    kelp_str_printf(&auth_val, "Bearer %s", p->api_key ? p->api_key : "");

    kelp_http_header_t *headers = NULL;
    kelp_http_header_add(&headers, "Content-Type", "application/json");
    kelp_http_header_add(&headers, "Authorization", auth_val.data);
    if (p->org_id) {
        kelp_http_header_add(&headers, "OpenAI-Organization", p->org_id);
    }

    kelp_str_free(&auth_val);

    const char *url = p->base_url ? p->base_url : OPENAI_API_URL;

    kelp_http_request_t req = {0};
    req.method  = "POST";
    req.url     = url;
    req.headers = headers;
    req.body    = body;
    req.body_len = strlen(body);
    req.timeout_ms = 120000;
    req.follow_redirects = true;

    kelp_http_response_t resp = {0};
    int rc = kelp_http_request(&req, &resp);

    if (rc == 0 && resp.body) {
        char *resp_body = (char *)malloc(resp.body_len + 1);
        if (resp_body) {
            memcpy(resp_body, resp.body, resp.body_len);
            resp_body[resp.body_len] = '\0';

            if (resp.status_code >= 200 && resp.status_code < 300) {
                rc = parse_response(resp_body, result);
            } else {
                KELP_ERROR("openai: HTTP %d: %s", resp.status_code, resp_body);
                rc = -1;
            }
            free(resp_body);
        } else {
            rc = -1;
        }
    } else if (rc != 0) {
        KELP_ERROR("openai: HTTP request failed");
    }

    kelp_http_response_free(&resp);
    free(body);
    kelp_http_header_free(headers);
    return rc;
}
