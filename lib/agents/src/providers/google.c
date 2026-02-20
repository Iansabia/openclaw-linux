/*
 * clawd-linux :: libclawd-agents
 * providers/google.c - Google Gemini API provider
 *
 * POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/provider.h>
#include <clawd/http.h>
#include <clawd/json.h>
#include <clawd/str.h>
#include <clawd/log.h>
#include <clawd/err.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define GOOGLE_API_BASE   "https://generativelanguage.googleapis.com/v1beta/models"
#define DEFAULT_MODEL     "gemini-pro"

/* ---- Forward declarations ----------------------------------------------- */

static int google_complete(clawd_provider_t *p,
                           const clawd_completion_opts_t *opts,
                           clawd_completion_t *result);

/* ---- Initialization ----------------------------------------------------- */

int clawd_provider_google_init(clawd_provider_t *p)
{
    if (!p) return -1;
    p->complete = google_complete;
    /* base_url will be constructed dynamically with model name */
    return 0;
}

/* ---- JSON construction -------------------------------------------------- */

/*
 * Build the Gemini API request body:
 * {
 *   "contents": [
 *     { "role": "user", "parts": [{"text": "..."}] },
 *     { "role": "model", "parts": [{"text": "..."}] }
 *   ],
 *   "systemInstruction": { "parts": [{"text": "..."}] },
 *   "generationConfig": { "maxOutputTokens": ..., "temperature": ... }
 * }
 */
static char *build_request_json(const clawd_provider_t *p,
                                 const clawd_completion_opts_t *opts)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    /* System instruction */
    if (opts->system_prompt) {
        cJSON *sys = cJSON_CreateObject();
        cJSON *parts = cJSON_CreateArray();
        cJSON *part = cJSON_CreateObject();
        cJSON_AddStringToObject(part, "text", opts->system_prompt);
        cJSON_AddItemToArray(parts, part);
        cJSON_AddItemToObject(sys, "parts", parts);
        cJSON_AddItemToObject(root, "systemInstruction", sys);
    }

    /* Contents (conversation history) */
    cJSON *contents = cJSON_CreateArray();
    if (!contents) {
        cJSON_Delete(root);
        return NULL;
    }

    for (clawd_message_t *msg = opts->messages; msg; msg = msg->next) {
        if (msg->role == CLAWD_ROLE_SYSTEM) continue;

        cJSON *content = cJSON_CreateObject();
        if (!content) continue;

        /* Map roles: user->user, assistant->model, tool->user */
        const char *role = "user";
        if (msg->role == CLAWD_ROLE_ASSISTANT) role = "model";

        cJSON_AddStringToObject(content, "role", role);

        cJSON *parts = cJSON_CreateArray();
        if (msg->content) {
            cJSON *part = cJSON_CreateObject();
            cJSON_AddStringToObject(part, "text", msg->content);
            cJSON_AddItemToArray(parts, part);
        }

        /* Tool call results */
        if (msg->role == CLAWD_ROLE_TOOL && msg->tool_name) {
            cJSON *part = cJSON_CreateObject();
            cJSON *func_resp = cJSON_CreateObject();
            cJSON_AddStringToObject(func_resp, "name", msg->tool_name);
            cJSON *response = cJSON_CreateObject();
            cJSON_AddStringToObject(response, "result", msg->content ? msg->content : "");
            cJSON_AddItemToObject(func_resp, "response", response);
            cJSON_AddItemToObject(part, "functionResponse", func_resp);
            cJSON_AddItemToArray(parts, part);
        }

        /* Tool use requests (assistant) */
        if (msg->role == CLAWD_ROLE_ASSISTANT && msg->tool_name) {
            cJSON *part = cJSON_CreateObject();
            cJSON *func_call = cJSON_CreateObject();
            cJSON_AddStringToObject(func_call, "name", msg->tool_name);
            if (msg->tool_args) {
                cJSON *args = cJSON_Parse(msg->tool_args);
                if (args) {
                    cJSON_AddItemToObject(func_call, "args", args);
                }
            }
            cJSON_AddItemToObject(part, "functionCall", func_call);
            cJSON_AddItemToArray(parts, part);
        }

        cJSON_AddItemToObject(content, "parts", parts);
        cJSON_AddItemToArray(contents, content);
    }

    cJSON_AddItemToObject(root, "contents", contents);

    /* Generation config */
    cJSON *gen_config = cJSON_CreateObject();
    if (opts->max_tokens > 0) {
        cJSON_AddNumberToObject(gen_config, "maxOutputTokens", opts->max_tokens);
    }
    if (opts->temperature >= 0.0f) {
        cJSON_AddNumberToObject(gen_config, "temperature", (double)opts->temperature);
    }
    cJSON_AddItemToObject(root, "generationConfig", gen_config);

    /* Tools (function declarations) */
    if (opts->tools_json) {
        cJSON *tools_in = cJSON_Parse(opts->tools_json);
        if (tools_in && cJSON_IsArray(tools_in)) {
            cJSON *tools_obj = cJSON_CreateObject();
            cJSON *func_decls = cJSON_CreateArray();

            cJSON *tool;
            cJSON_ArrayForEach(tool, tools_in) {
                const char *name = clawd_json_get_string(tool, "name");
                const char *desc = clawd_json_get_string(tool, "description");
                cJSON *input_schema = cJSON_GetObjectItem(tool, "input_schema");

                cJSON *decl = cJSON_CreateObject();
                if (name) cJSON_AddStringToObject(decl, "name", name);
                if (desc) cJSON_AddStringToObject(decl, "description", desc);
                if (input_schema) {
                    cJSON_AddItemToObject(decl, "parameters",
                                          cJSON_Duplicate(input_schema, 1));
                }
                cJSON_AddItemToArray(func_decls, decl);
            }

            cJSON_AddItemToObject(tools_obj, "functionDeclarations", func_decls);

            cJSON *tools_arr = cJSON_CreateArray();
            cJSON_AddItemToArray(tools_arr, tools_obj);
            cJSON_AddItemToObject(root, "tools", tools_arr);
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

static int parse_response(const char *body, clawd_completion_t *result)
{
    if (!body || !result) return -1;

    cJSON *root = cJSON_Parse(body);
    if (!root) {
        CLAWD_ERROR("google: failed to parse response JSON");
        return -1;
    }

    /* Check for error */
    cJSON *error_obj = cJSON_GetObjectItem(root, "error");
    if (error_obj) {
        const char *emsg = clawd_json_get_string(error_obj, "message");
        CLAWD_ERROR("google API error: %s", emsg ? emsg : "unknown");
        cJSON_Delete(root);
        return -1;
    }

    /* Candidates */
    cJSON *candidates = cJSON_GetObjectItem(root, "candidates");
    if (candidates && cJSON_IsArray(candidates)) {
        cJSON *cand = cJSON_GetArrayItem(candidates, 0);
        if (cand) {
            /* finish_reason */
            const char *finish = clawd_json_get_string(cand, "finishReason");
            if (finish) {
                if (strcmp(finish, "STOP") == 0) {
                    result->stop_reason = strdup("end_turn");
                } else if (strcmp(finish, "MAX_TOKENS") == 0) {
                    result->stop_reason = strdup("max_tokens");
                } else {
                    result->stop_reason = strdup(finish);
                }
            }

            cJSON *content = cJSON_GetObjectItem(cand, "content");
            if (content) {
                cJSON *parts = cJSON_GetObjectItem(content, "parts");
                if (parts && cJSON_IsArray(parts)) {
                    clawd_str_t text_buf = clawd_str_new();

                    cJSON *part;
                    cJSON_ArrayForEach(part, parts) {
                        const char *text = clawd_json_get_string(part, "text");
                        if (text) {
                            clawd_str_append_cstr(&text_buf, text);
                        }

                        cJSON *func_call = cJSON_GetObjectItem(part, "functionCall");
                        if (func_call) {
                            const char *name = clawd_json_get_string(func_call, "name");
                            cJSON *args = cJSON_GetObjectItem(func_call, "args");

                            clawd_message_t *tc = clawd_message_new(CLAWD_ROLE_ASSISTANT, NULL);
                            if (tc) {
                                if (name) tc->tool_name = strdup(name);
                                /* Generate a synthetic tool call ID */
                                clawd_str_t id = clawd_str_new();
                                clawd_str_printf(&id, "call_%s", name ? name : "unknown");
                                tc->tool_call_id = strdup(id.data);
                                clawd_str_free(&id);

                                if (args) {
                                    char *args_str = cJSON_PrintUnformatted(args);
                                    if (args_str) tc->tool_args = args_str;
                                }
                                clawd_message_append(&result->tool_calls, tc);
                                if (!result->stop_reason) {
                                    result->stop_reason = strdup("tool_use");
                                }
                            }
                        }
                    }

                    if (text_buf.len > 0) {
                        result->content = strdup(text_buf.data);
                    }
                    clawd_str_free(&text_buf);
                }
            }
        }
    }

    /* Usage metadata */
    cJSON *usage = cJSON_GetObjectItem(root, "usageMetadata");
    if (usage) {
        result->input_tokens  = clawd_json_get_int(usage, "promptTokenCount", 0);
        result->output_tokens = clawd_json_get_int(usage, "candidatesTokenCount", 0);
    }

    cJSON_Delete(root);
    return 0;
}

/* ---- Main completion ---------------------------------------------------- */

static int google_complete(clawd_provider_t *p,
                           const clawd_completion_opts_t *opts,
                           clawd_completion_t *result)
{
    if (!p || !opts || !result) return -1;

    memset(result, 0, sizeof(*result));

    char *body = build_request_json(p, opts);
    if (!body) {
        CLAWD_ERROR("google: failed to build request JSON");
        return -1;
    }

    /* Build URL: base/model:generateContent?key=... */
    const char *model = opts->model ? opts->model : DEFAULT_MODEL;
    clawd_str_t url = clawd_str_new();
    const char *base = p->base_url ? p->base_url : GOOGLE_API_BASE;
    clawd_str_printf(&url, "%s/%s:generateContent", base, model);
    if (p->api_key) {
        clawd_str_printf(&url, "?key=%s", p->api_key);
    }

    clawd_http_header_t *headers = NULL;
    clawd_http_header_add(&headers, "Content-Type", "application/json");

    clawd_http_request_t req = {0};
    req.method  = "POST";
    req.url     = url.data;
    req.headers = headers;
    req.body    = body;
    req.body_len = strlen(body);
    req.timeout_ms = 120000;
    req.follow_redirects = true;

    clawd_http_response_t resp = {0};
    int rc = clawd_http_request(&req, &resp);

    if (rc == 0 && resp.body) {
        char *resp_body = (char *)malloc(resp.body_len + 1);
        if (resp_body) {
            memcpy(resp_body, resp.body, resp.body_len);
            resp_body[resp.body_len] = '\0';

            if (resp.status_code >= 200 && resp.status_code < 300) {
                rc = parse_response(resp_body, result);
            } else {
                CLAWD_ERROR("google: HTTP %d: %s", resp.status_code, resp_body);
                rc = -1;
            }
            free(resp_body);
        } else {
            rc = -1;
        }
    } else if (rc != 0) {
        CLAWD_ERROR("google: HTTP request failed");
    }

    clawd_http_response_free(&resp);
    clawd_str_free(&url);
    free(body);
    clawd_http_header_free(headers);
    return rc;
}
