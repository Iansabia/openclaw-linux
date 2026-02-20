/*
 * clawd-linux :: libclawd-agents
 * providers/bedrock.c - AWS Bedrock provider (stub with SigV4 signing)
 *
 * This provider targets the Amazon Bedrock InvokeModel API.
 * Full SigV4 signing is stubbed out pending integration with an
 * AWS SDK or custom signing library.
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/provider.h>
#include <clawd/http.h>
#include <clawd/json.h>
#include <clawd/str.h>
#include <clawd/log.h>
#include <clawd/err.h>
#include <clawd/crypto.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BEDROCK_SERVICE    "bedrock-runtime"
#define DEFAULT_REGION     "us-east-1"
#define DEFAULT_MODEL      "anthropic.claude-3-sonnet-20240229-v1:0"

/* ---- Forward declarations ----------------------------------------------- */

static int bedrock_complete(clawd_provider_t *p,
                            const clawd_completion_opts_t *opts,
                            clawd_completion_t *result);

/* ---- Bedrock-specific context ------------------------------------------- */

typedef struct {
    char *region;
    char *access_key_id;
    char *secret_access_key;
    char *session_token;
} bedrock_ctx_t;

static void bedrock_free_ctx(void *ctx)
{
    if (!ctx) return;
    bedrock_ctx_t *bctx = (bedrock_ctx_t *)ctx;
    free(bctx->region);
    free(bctx->access_key_id);
    free(bctx->secret_access_key);
    free(bctx->session_token);
    free(bctx);
}

/* ---- Initialization ----------------------------------------------------- */

int clawd_provider_bedrock_init(clawd_provider_t *p)
{
    if (!p) return -1;
    p->complete = bedrock_complete;
    p->free_ctx = bedrock_free_ctx;

    bedrock_ctx_t *bctx = (bedrock_ctx_t *)calloc(1, sizeof(*bctx));
    if (!bctx) return -1;

    /* Read from environment variables (standard AWS config) */
    const char *region = getenv("AWS_REGION");
    bctx->region = strdup(region ? region : DEFAULT_REGION);

    const char *access_key = getenv("AWS_ACCESS_KEY_ID");
    if (access_key) bctx->access_key_id = strdup(access_key);

    const char *secret_key = getenv("AWS_SECRET_ACCESS_KEY");
    if (secret_key) bctx->secret_access_key = strdup(secret_key);

    const char *session_token = getenv("AWS_SESSION_TOKEN");
    if (session_token) bctx->session_token = strdup(session_token);

    p->ctx = bctx;
    return 0;
}

/* ---- AWS SigV4 signing (stub) ------------------------------------------- */

/*
 * This is a placeholder for AWS Signature Version 4 signing.
 *
 * A full implementation would:
 *   1. Create the canonical request (method, URI, query string, headers, payload hash)
 *   2. Create the string to sign (algorithm, timestamp, scope, canonical request hash)
 *   3. Calculate the signing key (HMAC chain: date, region, service, "aws4_request")
 *   4. Calculate the signature (HMAC-SHA256 of string to sign with signing key)
 *   5. Add the Authorization header
 *
 * For now we just add the headers that would be present and log a warning.
 */
static int sign_request(clawd_http_header_t **headers,
                        const char *method,
                        const char *url,
                        const char *body,
                        size_t body_len,
                        const bedrock_ctx_t *bctx)
{
    if (!bctx || !bctx->access_key_id || !bctx->secret_access_key) {
        CLAWD_ERROR("bedrock: AWS credentials not configured");
        return -1;
    }

    /* Date header in ISO 8601 basic format */
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    char amz_date[32];
    strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", &tm);
    char date_stamp[16];
    strftime(date_stamp, sizeof(date_stamp), "%Y%m%d", &tm);

    clawd_http_header_add(headers, "x-amz-date", amz_date);

    /* Content hash */
    uint8_t hash[32];
    clawd_sha256(body, body_len, hash);
    char hash_hex[65];
    clawd_sha256_hex(body, body_len, hash_hex);
    clawd_http_header_add(headers, "x-amz-content-sha256", hash_hex);

    /* Session token if present */
    if (bctx->session_token) {
        clawd_http_header_add(headers, "x-amz-security-token", bctx->session_token);
    }

    /*
     * TODO: Implement full SigV4 signing.
     *
     * Step 1: canonical_request = method + "\n" + uri + "\n" + query + "\n" +
     *         canonical_headers + "\n" + signed_headers + "\n" + payload_hash
     *
     * Step 2: string_to_sign = "AWS4-HMAC-SHA256\n" + timestamp + "\n" +
     *         date/region/service/aws4_request + "\n" + SHA256(canonical_request)
     *
     * Step 3: signing_key = HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date),
     *                              region), service), "aws4_request")
     *
     * Step 4: signature = HMAC(signing_key, string_to_sign)
     *
     * Step 5: Authorization = "AWS4-HMAC-SHA256 Credential=.../scope, " +
     *         "SignedHeaders=..., Signature=..."
     */

    /* Compute signing key chain */
    uint8_t k_date[32], k_region[32], k_service[32], k_signing[32];
    clawd_str_t secret_prefix = clawd_str_new();
    clawd_str_printf(&secret_prefix, "AWS4%s", bctx->secret_access_key);

    clawd_hmac_sha256(secret_prefix.data, secret_prefix.len,
                      date_stamp, strlen(date_stamp), k_date);
    clawd_hmac_sha256(k_date, 32,
                      bctx->region, strlen(bctx->region), k_region);
    clawd_hmac_sha256(k_region, 32,
                      BEDROCK_SERVICE, strlen(BEDROCK_SERVICE), k_service);
    clawd_hmac_sha256(k_service, 32,
                      "aws4_request", 12, k_signing);

    clawd_str_free(&secret_prefix);

    /* For a complete implementation, we would compute the canonical request,
     * string to sign, and final signature here.  For now, log a warning. */
    CLAWD_WARN("bedrock: SigV4 signing is a stub; requests will not authenticate");

    /* Placeholder Authorization header */
    clawd_str_t auth = clawd_str_new();
    clawd_str_printf(&auth,
        "AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, "
        "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, "
        "Signature=STUB_SIGNATURE",
        bctx->access_key_id, date_stamp, bctx->region, BEDROCK_SERVICE);
    clawd_http_header_add(headers, "Authorization", auth.data);
    clawd_str_free(&auth);

    return 0;
}

/* ---- JSON construction -------------------------------------------------- */

/*
 * Build the Bedrock InvokeModel request body.
 * When using the Anthropic model via Bedrock, the request format
 * matches the Anthropic Messages API.
 */
static char *build_request_json(const clawd_provider_t *p,
                                 const clawd_completion_opts_t *opts)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    const char *model = opts->model ? opts->model : DEFAULT_MODEL;
    (void)model;  /* model is part of the URL, not the body for Bedrock */

    int max_tokens = opts->max_tokens > 0 ? opts->max_tokens : 4096;
    cJSON_AddNumberToObject(root, "max_tokens", max_tokens);
    cJSON_AddStringToObject(root, "anthropic_version", "bedrock-2023-05-31");

    if (opts->system_prompt) {
        cJSON_AddStringToObject(root, "system", opts->system_prompt);
    }

    if (opts->temperature >= 0.0f) {
        cJSON_AddNumberToObject(root, "temperature", (double)opts->temperature);
    }

    /* Messages array (Anthropic format) */
    cJSON *messages = cJSON_CreateArray();
    for (clawd_message_t *msg = opts->messages; msg; msg = msg->next) {
        if (msg->role == CLAWD_ROLE_SYSTEM) continue;

        cJSON *jmsg = cJSON_CreateObject();
        const char *role = "user";
        if (msg->role == CLAWD_ROLE_ASSISTANT) role = "assistant";
        cJSON_AddStringToObject(jmsg, "role", role);
        if (msg->content) {
            cJSON_AddStringToObject(jmsg, "content", msg->content);
        }
        cJSON_AddItemToArray(messages, jmsg);
    }
    cJSON_AddItemToObject(root, "messages", messages);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json_str;
}

/* ---- Main completion ---------------------------------------------------- */

static int bedrock_complete(clawd_provider_t *p,
                            const clawd_completion_opts_t *opts,
                            clawd_completion_t *result)
{
    if (!p || !opts || !result) return -1;

    memset(result, 0, sizeof(*result));

    bedrock_ctx_t *bctx = (bedrock_ctx_t *)p->ctx;
    if (!bctx) {
        CLAWD_ERROR("bedrock: provider not initialized");
        return -1;
    }

    char *body = build_request_json(p, opts);
    if (!body) {
        CLAWD_ERROR("bedrock: failed to build request JSON");
        return -1;
    }

    /* Build URL */
    const char *model = opts->model ? opts->model : DEFAULT_MODEL;
    clawd_str_t url = clawd_str_new();
    if (p->base_url) {
        clawd_str_append_cstr(&url, p->base_url);
    } else {
        clawd_str_printf(&url,
            "https://%s.%s.amazonaws.com/model/%s/invoke",
            BEDROCK_SERVICE, bctx->region, model);
    }

    clawd_http_header_t *headers = NULL;
    clawd_http_header_add(&headers, "Content-Type", "application/json");
    clawd_http_header_add(&headers, "Accept", "application/json");

    /* Sign the request */
    int rc = sign_request(&headers, "POST", url.data, body, strlen(body), bctx);
    if (rc != 0) {
        clawd_str_free(&url);
        free(body);
        clawd_http_header_free(headers);
        return -1;
    }

    clawd_http_request_t req = {0};
    req.method  = "POST";
    req.url     = url.data;
    req.headers = headers;
    req.body    = body;
    req.body_len = strlen(body);
    req.timeout_ms = 120000;
    req.follow_redirects = true;

    clawd_http_response_t resp = {0};
    rc = clawd_http_request(&req, &resp);

    if (rc == 0 && resp.body) {
        char *resp_body = (char *)malloc(resp.body_len + 1);
        if (resp_body) {
            memcpy(resp_body, resp.body, resp.body_len);
            resp_body[resp.body_len] = '\0';

            if (resp.status_code >= 200 && resp.status_code < 300) {
                /* Parse as Anthropic Messages API response (Bedrock uses same format) */
                cJSON *root = cJSON_Parse(resp_body);
                if (root) {
                    /* Extract content */
                    cJSON *content = cJSON_GetObjectItem(root, "content");
                    if (content && cJSON_IsArray(content)) {
                        cJSON *block = cJSON_GetArrayItem(content, 0);
                        if (block) {
                            const char *text = clawd_json_get_string(block, "text");
                            if (text) result->content = strdup(text);
                        }
                    }
                    const char *stop = clawd_json_get_string(root, "stop_reason");
                    if (stop) result->stop_reason = strdup(stop);

                    cJSON *usage = cJSON_GetObjectItem(root, "usage");
                    if (usage) {
                        result->input_tokens  = clawd_json_get_int(usage, "input_tokens", 0);
                        result->output_tokens = clawd_json_get_int(usage, "output_tokens", 0);
                    }
                    result->model = strdup(model);
                    cJSON_Delete(root);
                } else {
                    CLAWD_ERROR("bedrock: failed to parse response");
                    rc = -1;
                }
            } else {
                CLAWD_ERROR("bedrock: HTTP %d: %s", resp.status_code, resp_body);
                rc = -1;
            }
            free(resp_body);
        } else {
            rc = -1;
        }
    } else if (rc != 0) {
        CLAWD_ERROR("bedrock: HTTP request failed");
    }

    clawd_http_response_free(&resp);
    clawd_str_free(&url);
    free(body);
    clawd_http_header_free(headers);
    return rc;
}
