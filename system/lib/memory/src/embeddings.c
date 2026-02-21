/*
 * kelp-linux :: libkelp-memory
 * embeddings.c - Embedding API client (OpenAI / local HTTP)
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/embeddings.h>
#include <kelp/log.h>

#include <curl/curl.h>
#include <cjson/cJSON.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ----------------------------------------------------------------------- */
/* Constants                                                                */
/* ----------------------------------------------------------------------- */

#define OPENAI_EMBED_URL   "https://api.openai.com/v1/embeddings"
#define OPENAI_MODEL       "text-embedding-3-small"
#define OPENAI_DIM         1536

#define LOCAL_EMBED_URL    "http://127.0.0.1:11434/api/embeddings"
#define LOCAL_DIM          384    /* typical for small local models */

#define HTTP_TIMEOUT_SECS  30

/* ----------------------------------------------------------------------- */
/* Internal structure                                                       */
/* ----------------------------------------------------------------------- */

struct kelp_embed_ctx {
    kelp_embed_provider_t  provider;
    char                   *api_key;
    char                   *base_url;
    CURL                   *curl;
};

/* ----------------------------------------------------------------------- */
/* curl write callback                                                      */
/* ----------------------------------------------------------------------- */

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} response_buf_t;

static size_t
write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    response_buf_t *buf = userdata;
    size_t bytes = size * nmemb;

    if (buf->len + bytes + 1 > buf->cap) {
        size_t new_cap = (buf->cap == 0) ? 4096 : buf->cap;
        while (new_cap < buf->len + bytes + 1)
            new_cap *= 2;
        char *tmp = realloc(buf->data, new_cap);
        if (!tmp) return 0;
        buf->data = tmp;
        buf->cap  = new_cap;
    }

    memcpy(buf->data + buf->len, ptr, bytes);
    buf->len += bytes;
    buf->data[buf->len] = '\0';
    return bytes;
}

/* ----------------------------------------------------------------------- */
/* Helpers                                                                  */
/* ----------------------------------------------------------------------- */

static char *
embed_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s);
    char *d = malloc(len + 1);
    if (d) memcpy(d, s, len + 1);
    return d;
}

/*
 * Build the JSON request body for the OpenAI embeddings API.
 * For a single text: {"model":"...","input":"<text>"}
 * For a batch:       {"model":"...","input":["<t1>","<t2>",...]}
 */
static char *
build_openai_request(const char **texts, int count)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    cJSON_AddStringToObject(root, "model", OPENAI_MODEL);

    if (count == 1) {
        cJSON_AddStringToObject(root, "input", texts[0]);
    } else {
        cJSON *arr = cJSON_AddArrayToObject(root, "input");
        for (int i = 0; i < count; i++) {
            cJSON_AddItemToArray(arr, cJSON_CreateString(texts[i]));
        }
    }

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json;
}

/*
 * Build the JSON request body for a local embedding server
 * (Ollama-compatible format).
 */
static char *
build_local_request(const char *text)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    cJSON_AddStringToObject(root, "model", "all-minilm");
    cJSON_AddStringToObject(root, "prompt", text);

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json;
}

/*
 * Parse the OpenAI embeddings API response.
 * Extracts float arrays from:
 * {"data":[{"embedding":[f1,f2,...,fn],"index":0},...],...}
 *
 * Returns 0 on success and sets *embeddings and *dim.
 */
static int
parse_openai_response(const char *json, int expected_count,
                      float **embeddings, int *dim)
{
    cJSON *root = cJSON_Parse(json);
    if (!root) {
        KELP_ERROR("embeddings: failed to parse JSON response");
        return -1;
    }

    /* Check for error. */
    cJSON *err = cJSON_GetObjectItemCaseSensitive(root, "error");
    if (err) {
        cJSON *msg = cJSON_GetObjectItemCaseSensitive(err, "message");
        KELP_ERROR("embeddings API error: %s",
                    msg ? msg->valuestring : "unknown");
        cJSON_Delete(root);
        return -1;
    }

    cJSON *data = cJSON_GetObjectItemCaseSensitive(root, "data");
    if (!cJSON_IsArray(data)) {
        KELP_ERROR("embeddings: 'data' is not an array");
        cJSON_Delete(root);
        return -1;
    }

    int n_items = cJSON_GetArraySize(data);
    if (n_items < 1) {
        KELP_ERROR("embeddings: empty data array");
        cJSON_Delete(root);
        return -1;
    }

    /* Determine dimension from first embedding. */
    cJSON *first = cJSON_GetArrayItem(data, 0);
    cJSON *first_emb = cJSON_GetObjectItemCaseSensitive(first, "embedding");
    if (!cJSON_IsArray(first_emb)) {
        KELP_ERROR("embeddings: first embedding is not an array");
        cJSON_Delete(root);
        return -1;
    }

    int d = cJSON_GetArraySize(first_emb);
    if (d <= 0) {
        KELP_ERROR("embeddings: zero-dimension embedding");
        cJSON_Delete(root);
        return -1;
    }

    /* Allocate flat array: n_items * d floats. */
    float *out = calloc((size_t)n_items * (size_t)d, sizeof(float));
    if (!out) {
        cJSON_Delete(root);
        return -1;
    }

    for (int i = 0; i < n_items; i++) {
        cJSON *item = cJSON_GetArrayItem(data, i);
        cJSON *emb  = cJSON_GetObjectItemCaseSensitive(item, "embedding");
        if (!cJSON_IsArray(emb) || cJSON_GetArraySize(emb) != d) {
            free(out);
            cJSON_Delete(root);
            return -1;
        }

        for (int j = 0; j < d; j++) {
            cJSON *val = cJSON_GetArrayItem(emb, j);
            out[i * d + j] = (float)val->valuedouble;
        }
    }

    *embeddings = out;
    *dim        = d;
    cJSON_Delete(root);
    return 0;
}

/*
 * Parse a local embedding server response (Ollama-style).
 * {"embedding":[f1,f2,...,fn]}
 */
static int
parse_local_response(const char *json, float **embedding, int *dim)
{
    cJSON *root = cJSON_Parse(json);
    if (!root) {
        KELP_ERROR("embeddings: failed to parse local response");
        return -1;
    }

    cJSON *emb = cJSON_GetObjectItemCaseSensitive(root, "embedding");
    if (!cJSON_IsArray(emb)) {
        KELP_ERROR("embeddings: 'embedding' is not an array");
        cJSON_Delete(root);
        return -1;
    }

    int d = cJSON_GetArraySize(emb);
    if (d <= 0) {
        cJSON_Delete(root);
        return -1;
    }

    float *out = calloc((size_t)d, sizeof(float));
    if (!out) {
        cJSON_Delete(root);
        return -1;
    }

    for (int i = 0; i < d; i++) {
        cJSON *val = cJSON_GetArrayItem(emb, i);
        out[i] = (float)val->valuedouble;
    }

    *embedding = out;
    *dim       = d;
    cJSON_Delete(root);
    return 0;
}

/*
 * Perform an HTTP POST with JSON body and collect the response.
 */
static int
http_post_json(CURL *curl, const char *url, const char *api_key,
               const char *body, response_buf_t *resp)
{
    if (!curl || !url || !body) return -1;

    curl_easy_reset(curl);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    if (api_key && api_key[0]) {
        char auth[512];
        snprintf(auth, sizeof(auth), "Authorization: Bearer %s", api_key);
        headers = curl_slist_append(headers, auth);
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)HTTP_TIMEOUT_SECS);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode cc = curl_easy_perform(curl);
    curl_slist_free_all(headers);

    if (cc != CURLE_OK) {
        KELP_ERROR("embeddings HTTP request failed: %s",
                    curl_easy_strerror(cc));
        return -1;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code < 200 || http_code >= 300) {
        KELP_ERROR("embeddings HTTP %ld: %.*s",
                    http_code,
                    (int)(resp->len > 256 ? 256 : resp->len),
                    resp->data ? resp->data : "");
        return -1;
    }

    return 0;
}

/* ----------------------------------------------------------------------- */
/* Public API                                                               */
/* ----------------------------------------------------------------------- */

kelp_embed_ctx_t *
kelp_embed_ctx_new(kelp_embed_provider_t provider, const char *api_key)
{
    kelp_embed_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->provider = provider;
    ctx->api_key  = api_key ? embed_strdup(api_key) : NULL;

    switch (provider) {
    case KELP_EMBED_OPENAI:
        ctx->base_url = embed_strdup(OPENAI_EMBED_URL);
        break;
    case KELP_EMBED_LOCAL:
        ctx->base_url = embed_strdup(LOCAL_EMBED_URL);
        break;
    default:
        free(ctx);
        return NULL;
    }

    ctx->curl = curl_easy_init();
    if (!ctx->curl) {
        free(ctx->api_key);
        free(ctx->base_url);
        free(ctx);
        return NULL;
    }

    return ctx;
}

void
kelp_embed_ctx_free(kelp_embed_ctx_t *ctx)
{
    if (!ctx) return;
    if (ctx->curl) curl_easy_cleanup(ctx->curl);
    free(ctx->api_key);
    free(ctx->base_url);
    free(ctx);
}

int
kelp_embed_text(kelp_embed_ctx_t *ctx, const char *text,
                  float **embedding, int *dim)
{
    if (!ctx || !text || !embedding || !dim) return -1;

    *embedding = NULL;
    *dim       = 0;

    response_buf_t resp = {0};

    if (ctx->provider == KELP_EMBED_OPENAI) {
        const char *texts[1] = { text };
        char *body = build_openai_request(texts, 1);
        if (!body) return -1;

        int rc = http_post_json(ctx->curl, ctx->base_url, ctx->api_key,
                                body, &resp);
        free(body);
        if (rc != 0) {
            free(resp.data);
            return -1;
        }

        rc = parse_openai_response(resp.data, 1, embedding, dim);
        free(resp.data);
        return rc;

    } else if (ctx->provider == KELP_EMBED_LOCAL) {
        char *body = build_local_request(text);
        if (!body) return -1;

        int rc = http_post_json(ctx->curl, ctx->base_url, ctx->api_key,
                                body, &resp);
        free(body);
        if (rc != 0) {
            free(resp.data);
            return -1;
        }

        rc = parse_local_response(resp.data, embedding, dim);
        free(resp.data);
        return rc;
    }

    return -1;
}

int
kelp_embed_batch(kelp_embed_ctx_t *ctx, const char **texts, int count,
                   float **embeddings, int *dim)
{
    if (!ctx || !texts || count <= 0 || !embeddings || !dim) return -1;

    *embeddings = NULL;
    *dim        = 0;

    if (ctx->provider == KELP_EMBED_OPENAI) {
        /* OpenAI supports batch natively. */
        char *body = build_openai_request(texts, count);
        if (!body) return -1;

        response_buf_t resp = {0};
        int rc = http_post_json(ctx->curl, ctx->base_url, ctx->api_key,
                                body, &resp);
        free(body);
        if (rc != 0) {
            free(resp.data);
            return -1;
        }

        rc = parse_openai_response(resp.data, count, embeddings, dim);
        free(resp.data);
        return rc;

    } else if (ctx->provider == KELP_EMBED_LOCAL) {
        /*
         * Local providers typically don't support batch.
         * Embed each text individually and concatenate.
         */
        int d = 0;
        float *all = NULL;

        for (int i = 0; i < count; i++) {
            float *emb = NULL;
            int edim = 0;

            int rc = kelp_embed_text(ctx, texts[i], &emb, &edim);
            if (rc != 0) {
                free(all);
                return -1;
            }

            if (i == 0) {
                d = edim;
                all = calloc((size_t)count * (size_t)d, sizeof(float));
                if (!all) {
                    free(emb);
                    return -1;
                }
            } else if (edim != d) {
                KELP_ERROR("embeddings: inconsistent dimensions (%d vs %d)",
                            edim, d);
                free(emb);
                free(all);
                return -1;
            }

            memcpy(all + (size_t)i * (size_t)d, emb,
                   (size_t)d * sizeof(float));
            free(emb);
        }

        *embeddings = all;
        *dim        = d;
        return 0;
    }

    return -1;
}

int
kelp_embed_dimension(kelp_embed_provider_t provider)
{
    switch (provider) {
    case KELP_EMBED_OPENAI: return OPENAI_DIM;
    case KELP_EMBED_LOCAL:  return LOCAL_DIM;
    default:                 return -1;
    }
}
