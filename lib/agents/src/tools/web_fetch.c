/*
 * clawd-linux :: libclawd-agents
 * tools/web_fetch.c - Web fetch tool (HTTP GET)
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/tool.h>
#include <clawd/http.h>
#include <clawd/json.h>
#include <clawd/str.h>
#include <clawd/log.h>

#include <stdlib.h>
#include <string.h>

#define WEB_FETCH_NAME        "web_fetch"
#define WEB_FETCH_DESCRIPTION "Fetch the contents of a URL via HTTP GET."
#define WEB_FETCH_PARAMS \
    "{\"type\":\"object\"," \
    "\"properties\":{" \
        "\"url\":{\"type\":\"string\",\"description\":\"The URL to fetch\"}," \
        "\"timeout\":{\"type\":\"integer\",\"description\":\"Timeout in milliseconds (default 30000)\"}" \
    "}," \
    "\"required\":[\"url\"]}"

#define DEFAULT_TIMEOUT_MS  30000
#define MAX_RESPONSE_SIZE   (1024 * 1024)  /* 1 MB max response */

static int web_fetch_exec(clawd_tool_ctx_t *ctx, const char *args_json,
                          clawd_tool_result_t *result)
{
    if (!result) return -1;

    memset(result, 0, sizeof(*result));

    /* Parse arguments */
    cJSON *args = cJSON_Parse(args_json);
    if (!args) {
        result->output   = strdup("error: invalid JSON arguments");
        result->is_error = true;
        result->exit_code = -1;
        return -1;
    }

    const char *url = clawd_json_get_string(args, "url");
    if (!url) {
        result->output   = strdup("error: 'url' parameter is required");
        result->is_error = true;
        result->exit_code = -1;
        cJSON_Delete(args);
        return -1;
    }

    int timeout_ms = clawd_json_get_int(args, "timeout", DEFAULT_TIMEOUT_MS);

    CLAWD_DEBUG("web_fetch: %s", url);

    /* Perform HTTP GET */
    clawd_http_header_t *headers = NULL;
    clawd_http_header_add(&headers, "User-Agent", "clawd-agent/0.1");
    clawd_http_header_add(&headers, "Accept", "text/html,application/json,text/plain,*/*");

    clawd_http_request_t req = {0};
    req.method  = "GET";
    req.url     = url;
    req.headers = headers;
    req.timeout_ms = timeout_ms;
    req.follow_redirects = true;

    clawd_http_response_t resp = {0};
    int rc = clawd_http_request(&req, &resp);

    if (rc != 0) {
        result->output   = strdup("error: HTTP request failed");
        result->is_error = true;
        result->exit_code = 1;
    } else if (resp.status_code >= 400) {
        clawd_str_t err = clawd_str_new();
        clawd_str_printf(&err, "error: HTTP %d", resp.status_code);
        if (resp.body && resp.body_len > 0) {
            size_t show_len = resp.body_len;
            if (show_len > 500) show_len = 500;
            clawd_str_append_cstr(&err, "\n");
            clawd_str_append(&err, (const char *)resp.body, show_len);
        }
        result->output   = err.data ? strdup(err.data) : strdup("error: HTTP error");
        result->is_error = true;
        result->exit_code = 1;
        clawd_str_free(&err);
    } else if (resp.body && resp.body_len > 0) {
        /* Truncate very large responses */
        size_t len = resp.body_len;
        bool truncated = false;
        if (len > MAX_RESPONSE_SIZE) {
            len = MAX_RESPONSE_SIZE;
            truncated = true;
        }

        clawd_str_t out = clawd_str_new();
        clawd_str_printf(&out, "HTTP %d", resp.status_code);
        if (resp.content_type) {
            clawd_str_printf(&out, " (%s)", resp.content_type);
        }
        clawd_str_append_cstr(&out, "\n\n");
        clawd_str_append(&out, (const char *)resp.body, len);

        if (truncated) {
            clawd_str_printf(&out, "\n\n[truncated: %zu of %zu bytes shown]",
                             len, resp.body_len);
        }

        result->output   = out.data ? strdup(out.data) : strdup("");
        result->is_error = false;
        result->exit_code = 0;
        clawd_str_free(&out);
    } else {
        clawd_str_t out = clawd_str_new();
        clawd_str_printf(&out, "HTTP %d (empty response)", resp.status_code);
        result->output   = out.data ? strdup(out.data) : strdup("");
        result->is_error = false;
        result->exit_code = 0;
        clawd_str_free(&out);
    }

    clawd_http_response_free(&resp);
    clawd_http_header_free(headers);
    cJSON_Delete(args);
    return 0;
}

/* ---- Registration ------------------------------------------------------- */

const clawd_tool_def_t clawd_web_fetch_tool_def = {
    .name                 = WEB_FETCH_NAME,
    .description          = WEB_FETCH_DESCRIPTION,
    .params_json          = WEB_FETCH_PARAMS,
    .exec                 = web_fetch_exec,
    .requires_sandbox     = false,
    .requires_confirmation = false
};
