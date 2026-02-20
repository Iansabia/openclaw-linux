/*
 * clawd-linux :: libclawd-agents
 * providers/ollama.c - Ollama local inference provider
 *
 * POST http://localhost:11434/api/chat
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/provider.h>
#include <clawd/http.h>
#include <clawd/json.h>
#include <clawd/str.h>
#include <clawd/log.h>
#include <clawd/err.h>

#include <stdlib.h>
#include <string.h>

#define OLLAMA_API_URL     "http://localhost:11434/api/chat"
#define DEFAULT_MODEL      "llama3"

/* ---- Forward declarations ----------------------------------------------- */

static int ollama_complete(clawd_provider_t *p,
                           const clawd_completion_opts_t *opts,
                           clawd_completion_t *result);

/* ---- Initialization ----------------------------------------------------- */

int clawd_provider_ollama_init(clawd_provider_t *p)
{
    if (!p) return -1;
    p->complete = ollama_complete;
    if (!p->base_url) {
        p->base_url = strdup(OLLAMA_API_URL);
    }
    return 0;
}

/* ---- JSON construction -------------------------------------------------- */

static char *build_request_json(const clawd_provider_t *p,
                                 const clawd_completion_opts_t *opts)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    const char *model = opts->model ? opts->model : DEFAULT_MODEL;
    cJSON_AddStringToObject(root, "model", model);
    cJSON_AddBoolToObject(root, "stream", 0);  /* synchronous for now */

    /* Build messages array */
    cJSON *messages = cJSON_CreateArray();
    if (!messages) {
        cJSON_Delete(root);
        return NULL;
    }

    /* System prompt */
    if (opts->system_prompt) {
        cJSON *sys = cJSON_CreateObject();
        cJSON_AddStringToObject(sys, "role", "system");
        cJSON_AddStringToObject(sys, "content", opts->system_prompt);
        cJSON_AddItemToArray(messages, sys);
    }

    for (clawd_message_t *msg = opts->messages; msg; msg = msg->next) {
        if (msg->role == CLAWD_ROLE_SYSTEM) continue;

        cJSON *jmsg = cJSON_CreateObject();
        if (!jmsg) continue;

        switch (msg->role) {
        case CLAWD_ROLE_USER:
            cJSON_AddStringToObject(jmsg, "role", "user");
            break;
        case CLAWD_ROLE_ASSISTANT:
            cJSON_AddStringToObject(jmsg, "role", "assistant");
            break;
        case CLAWD_ROLE_TOOL:
            cJSON_AddStringToObject(jmsg, "role", "user");
            break;
        default:
            cJSON_AddStringToObject(jmsg, "role", "user");
            break;
        }

        if (msg->content) {
            cJSON_AddStringToObject(jmsg, "content", msg->content);
        }

        cJSON_AddItemToArray(messages, jmsg);
    }

    cJSON_AddItemToObject(root, "messages", messages);

    /* Options */
    if (opts->temperature >= 0.0f) {
        cJSON *options = cJSON_CreateObject();
        cJSON_AddNumberToObject(options, "temperature", (double)opts->temperature);
        if (opts->max_tokens > 0) {
            cJSON_AddNumberToObject(options, "num_predict", opts->max_tokens);
        }
        cJSON_AddItemToObject(root, "options", options);
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
        CLAWD_ERROR("ollama: failed to parse response JSON");
        return -1;
    }

    /* Check for error */
    const char *error_msg = clawd_json_get_string(root, "error");
    if (error_msg) {
        CLAWD_ERROR("ollama API error: %s", error_msg);
        cJSON_Delete(root);
        return -1;
    }

    /* Model */
    const char *model = clawd_json_get_string(root, "model");
    if (model) result->model = strdup(model);

    /* Message content */
    cJSON *message = cJSON_GetObjectItem(root, "message");
    if (message) {
        const char *content = clawd_json_get_string(message, "content");
        if (content) result->content = strdup(content);
    }

    /* Ollama reports done_reason */
    bool done = clawd_json_get_bool(root, "done", false);
    if (done) {
        result->stop_reason = strdup("end_turn");
    }

    /* Token counts */
    result->input_tokens  = clawd_json_get_int(root, "prompt_eval_count", 0);
    result->output_tokens = clawd_json_get_int(root, "eval_count", 0);

    cJSON_Delete(root);
    return 0;
}

/* ---- Main completion ---------------------------------------------------- */

static int ollama_complete(clawd_provider_t *p,
                           const clawd_completion_opts_t *opts,
                           clawd_completion_t *result)
{
    if (!p || !opts || !result) return -1;

    memset(result, 0, sizeof(*result));

    char *body = build_request_json(p, opts);
    if (!body) {
        CLAWD_ERROR("ollama: failed to build request JSON");
        return -1;
    }

    clawd_http_header_t *headers = NULL;
    clawd_http_header_add(&headers, "Content-Type", "application/json");

    const char *url = p->base_url ? p->base_url : OLLAMA_API_URL;

    clawd_http_request_t req = {0};
    req.method  = "POST";
    req.url     = url;
    req.headers = headers;
    req.body    = body;
    req.body_len = strlen(body);
    req.timeout_ms = 300000;  /* 5 minutes for local models */
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
                CLAWD_ERROR("ollama: HTTP %d: %s", resp.status_code, resp_body);
                rc = -1;
            }
            free(resp_body);
        } else {
            rc = -1;
        }
    } else if (rc != 0) {
        CLAWD_ERROR("ollama: HTTP request failed (is Ollama running?)");
    }

    clawd_http_response_free(&resp);
    free(body);
    clawd_http_header_free(headers);
    return rc;
}
