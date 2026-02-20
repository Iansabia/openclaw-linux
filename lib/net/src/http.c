/*
 * clawd-linux :: libclawd-net
 * http.c - HTTP client implementation (libcurl backend)
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/http.h>
#include <clawd/err.h>
#include <clawd/log.h>

#include <curl/curl.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define CLAWD_USER_AGENT "clawd-linux/0.1.0"

/* ---- Internal helpers --------------------------------------------------- */

/** Write-callback context for collecting the full response body. */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} write_buf_t;

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *ud)
{
    write_buf_t *wb = (write_buf_t *)ud;
    size_t bytes = size * nmemb;

    if (wb->len + bytes + 1 > wb->cap) {
        size_t new_cap = (wb->cap == 0) ? 4096 : wb->cap;
        while (new_cap < wb->len + bytes + 1)
            new_cap *= 2;
        uint8_t *tmp = realloc(wb->data, new_cap);
        if (!tmp)
            return 0; /* signal error to curl */
        wb->data = tmp;
        wb->cap  = new_cap;
    }

    memcpy(wb->data + wb->len, ptr, bytes);
    wb->len += bytes;
    wb->data[wb->len] = '\0'; /* keep NUL-terminated for convenience */
    return bytes;
}

/** Write-callback context for header collection. */
typedef struct {
    clawd_http_header_t **list;
    char                 *content_type; /* extracted for convenience */
} header_ctx_t;

static size_t header_cb(char *buf, size_t size, size_t nmemb, void *ud)
{
    header_ctx_t *ctx = (header_ctx_t *)ud;
    size_t total = size * nmemb;

    /* Skip the status line and empty lines */
    if (total < 3 || buf[0] == '\r' || buf[0] == '\n')
        return total;

    /* Find the colon separator */
    char *colon = memchr(buf, ':', total);
    if (!colon)
        return total;

    size_t name_len = (size_t)(colon - buf);
    char *name = malloc(name_len + 1);
    if (!name)
        return 0;
    memcpy(name, buf, name_len);
    name[name_len] = '\0';

    /* Skip colon and leading whitespace in value */
    char *vstart = colon + 1;
    size_t remaining = total - name_len - 1;
    while (remaining > 0 && (*vstart == ' ' || *vstart == '\t')) {
        vstart++;
        remaining--;
    }
    /* Strip trailing \r\n */
    while (remaining > 0 &&
           (vstart[remaining - 1] == '\r' || vstart[remaining - 1] == '\n'))
        remaining--;

    char *value = malloc(remaining + 1);
    if (!value) {
        free(name);
        return 0;
    }
    memcpy(value, vstart, remaining);
    value[remaining] = '\0';

    /* Extract Content-Type for convenience */
    if (strcasecmp(name, "Content-Type") == 0) {
        free(ctx->content_type);
        ctx->content_type = strdup(value);
    }

    /* Prepend to the header list */
    clawd_http_header_t *hdr = calloc(1, sizeof(*hdr));
    if (!hdr) {
        free(name);
        free(value);
        return 0;
    }
    hdr->name  = name;
    hdr->value = value;
    hdr->next  = *ctx->list;
    *ctx->list = hdr;

    return total;
}

/** Convert our header list into a curl_slist. */
static struct curl_slist *headers_to_slist(const clawd_http_header_t *list)
{
    struct curl_slist *slist = NULL;
    char hdr_line[2048];

    for (const clawd_http_header_t *h = list; h; h = h->next) {
        snprintf(hdr_line, sizeof(hdr_line), "%s: %s", h->name, h->value);
        slist = curl_slist_append(slist, hdr_line);
    }
    return slist;
}

/** Apply common CURL options from a request struct. */
static void apply_common_opts(CURL *curl, const clawd_http_request_t *req,
                              struct curl_slist *slist)
{
    curl_easy_setopt(curl, CURLOPT_URL, req->url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, CLAWD_USER_AGENT);

    if (req->timeout_ms > 0)
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)req->timeout_ms);

    if (req->follow_redirects)
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    else
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);

    if (req->ca_bundle)
        curl_easy_setopt(curl, CURLOPT_CAINFO, req->ca_bundle);

    if (slist)
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

    /* Set HTTP method and body */
    if (req->method) {
        if (strcmp(req->method, "POST") == 0) {
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
        } else if (strcmp(req->method, "PUT") == 0) {
            curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        } else if (strcmp(req->method, "HEAD") == 0) {
            curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        } else if (strcmp(req->method, "GET") != 0) {
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, req->method);
        }
    }

    if (req->body && req->body_len > 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req->body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)req->body_len);
    }

    /* Disable signals for thread safety */
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
}

/* ---- Streaming callback adapter ----------------------------------------- */

typedef struct {
    clawd_http_stream_cb cb;
    void                *userdata;
    int                  aborted;
} stream_ctx_t;

static size_t stream_write_cb(char *ptr, size_t size, size_t nmemb, void *ud)
{
    stream_ctx_t *ctx = (stream_ctx_t *)ud;
    size_t bytes = size * nmemb;

    if (ctx->aborted)
        return 0;

    if (ctx->cb(ptr, bytes, ctx->userdata) != 0) {
        ctx->aborted = 1;
        return 0; /* abort transfer */
    }
    return bytes;
}

/* ---- SSE parser --------------------------------------------------------- */

/**
 * SSE parser state.
 *
 * SSE events are separated by blank lines (\n\n).  Each line is either
 * a field (e.g. "data: ...", "event: ...", "id: ...") or a comment
 * (starts with ':').
 */
typedef struct {
    clawd_sse_cb  cb;
    void         *userdata;
    int           aborted;

    /* Accumulation buffers for the current event */
    char *event_type;     /* from "event:" field */
    char *data_buf;       /* accumulated "data:" fields, joined by \n */
    size_t data_len;
    size_t data_cap;
    char *last_id;        /* from "id:" field */

    /* Line buffer for incomplete lines */
    char  *line_buf;
    size_t line_len;
    size_t line_cap;
} sse_ctx_t;

static void sse_ctx_init(sse_ctx_t *ctx, clawd_sse_cb cb, void *ud)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->cb       = cb;
    ctx->userdata = ud;
}

static void sse_ctx_free(sse_ctx_t *ctx)
{
    free(ctx->event_type);
    free(ctx->data_buf);
    free(ctx->last_id);
    free(ctx->line_buf);
    memset(ctx, 0, sizeof(*ctx));
}

static void sse_dispatch(sse_ctx_t *ctx)
{
    /* Only dispatch if we have data */
    if (!ctx->data_buf || ctx->data_len == 0)
        goto reset;

    /* Remove trailing newline from data if present */
    if (ctx->data_len > 0 && ctx->data_buf[ctx->data_len - 1] == '\n') {
        ctx->data_buf[ctx->data_len - 1] = '\0';
        ctx->data_len--;
    }

    clawd_sse_event_t ev = {
        .event = ctx->event_type,
        .data  = ctx->data_buf,
        .id    = ctx->last_id
    };

    if (ctx->cb(&ev, ctx->userdata) != 0)
        ctx->aborted = 1;

reset:
    free(ctx->event_type);
    ctx->event_type = NULL;
    free(ctx->data_buf);
    ctx->data_buf = NULL;
    ctx->data_len = 0;
    ctx->data_cap = 0;
    /* last_id persists across events per the SSE spec */
}

static void sse_append_data(sse_ctx_t *ctx, const char *text, size_t len)
{
    /* +2 for newline separator and NUL */
    size_t needed = ctx->data_len + len + 2;
    if (needed > ctx->data_cap) {
        size_t new_cap = ctx->data_cap ? ctx->data_cap : 256;
        while (new_cap < needed)
            new_cap *= 2;
        char *tmp = realloc(ctx->data_buf, new_cap);
        if (!tmp)
            return;
        ctx->data_buf = tmp;
        ctx->data_cap = new_cap;
    }

    memcpy(ctx->data_buf + ctx->data_len, text, len);
    ctx->data_len += len;
    ctx->data_buf[ctx->data_len++] = '\n';
    ctx->data_buf[ctx->data_len] = '\0';
}

static void sse_process_line(sse_ctx_t *ctx, const char *line, size_t len)
{
    /* Empty line = dispatch event */
    if (len == 0) {
        sse_dispatch(ctx);
        return;
    }

    /* Comment lines start with ':' */
    if (line[0] == ':')
        return;

    /* Find field name/value separator */
    const char *colon = memchr(line, ':', len);
    const char *field_name = line;
    size_t field_len;
    const char *value;
    size_t value_len;

    if (colon) {
        field_len = (size_t)(colon - line);
        value = colon + 1;
        value_len = len - field_len - 1;
        /* Skip single leading space after colon */
        if (value_len > 0 && value[0] == ' ') {
            value++;
            value_len--;
        }
    } else {
        field_len = len;
        value = "";
        value_len = 0;
    }

    if (field_len == 4 && memcmp(field_name, "data", 4) == 0) {
        sse_append_data(ctx, value, value_len);
    } else if (field_len == 5 && memcmp(field_name, "event", 5) == 0) {
        free(ctx->event_type);
        ctx->event_type = strndup(value, value_len);
    } else if (field_len == 2 && memcmp(field_name, "id", 2) == 0) {
        /* id field must not contain NUL */
        if (!memchr(value, '\0', value_len)) {
            free(ctx->last_id);
            ctx->last_id = strndup(value, value_len);
        }
    }
    /* "retry" and unknown fields are ignored */
}

static void sse_feed(sse_ctx_t *ctx, const char *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        char c = data[i];

        if (c == '\n' || c == '\r') {
            /* Handle \r\n as a single line ending */
            if (c == '\r' && i + 1 < len && data[i + 1] == '\n')
                i++;

            /* Process the completed line */
            sse_process_line(ctx, ctx->line_buf ? ctx->line_buf : "",
                             ctx->line_len);
            ctx->line_len = 0;
            continue;
        }

        /* Append character to line buffer */
        if (ctx->line_len + 2 > ctx->line_cap) {
            size_t new_cap = ctx->line_cap ? ctx->line_cap * 2 : 256;
            char *tmp = realloc(ctx->line_buf, new_cap);
            if (!tmp)
                return;
            ctx->line_buf = tmp;
            ctx->line_cap = new_cap;
        }
        ctx->line_buf[ctx->line_len++] = c;
        ctx->line_buf[ctx->line_len] = '\0';
    }
}

static size_t sse_write_cb(char *ptr, size_t size, size_t nmemb, void *ud)
{
    sse_ctx_t *ctx = (sse_ctx_t *)ud;
    size_t bytes = size * nmemb;

    if (ctx->aborted)
        return 0;

    sse_feed(ctx, ptr, bytes);

    if (ctx->aborted)
        return 0;

    return bytes;
}

/* ---- Public API --------------------------------------------------------- */

int clawd_http_init(void)
{
    CURLcode rc = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (rc != CURLE_OK) {
        CLAWD_ERROR("curl_global_init failed: %s", curl_easy_strerror(rc));
        return CLAWD_ERR_INTERNAL;
    }
    CLAWD_DEBUG("HTTP subsystem initialized");
    return CLAWD_OK;
}

void clawd_http_cleanup(void)
{
    curl_global_cleanup();
    CLAWD_DEBUG("HTTP subsystem cleaned up");
}

int clawd_http_request(const clawd_http_request_t *req,
                       clawd_http_response_t *resp)
{
    if (!req || !resp)
        return CLAWD_ERR_INVALID;

    memset(resp, 0, sizeof(*resp));

    CURL *curl = curl_easy_init();
    if (!curl) {
        CLAWD_ERROR("curl_easy_init failed");
        return CLAWD_ERR_INTERNAL;
    }

    struct curl_slist *slist = headers_to_slist(req->headers);

    /* Response body collection */
    write_buf_t wb = {0};
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &wb);

    /* Response header collection */
    header_ctx_t hctx = { .list = &resp->headers, .content_type = NULL };
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &hctx);

    apply_common_opts(curl, req, slist);

    CURLcode rc = curl_easy_perform(curl);

    int result = CLAWD_OK;
    if (rc != CURLE_OK) {
        if (rc == CURLE_OPERATION_TIMEDOUT) {
            CLAWD_WARN("HTTP request timed out: %s", req->url);
            result = CLAWD_ERR_TIMEOUT;
        } else {
            CLAWD_ERROR("HTTP request failed: %s", curl_easy_strerror(rc));
            result = CLAWD_ERR_NET;
        }
        free(wb.data);
        free(hctx.content_type);
    } else {
        long status = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        resp->status_code  = (int)status;
        resp->body         = wb.data;
        resp->body_len     = wb.len;
        resp->content_type = hctx.content_type;
    }

    curl_slist_free_all(slist);
    curl_easy_cleanup(curl);
    return result;
}

int clawd_http_stream(const clawd_http_request_t *req,
                      clawd_http_stream_cb cb, void *userdata)
{
    if (!req || !cb)
        return CLAWD_ERR_INVALID;

    CURL *curl = curl_easy_init();
    if (!curl)
        return CLAWD_ERR_INTERNAL;

    struct curl_slist *slist = headers_to_slist(req->headers);

    stream_ctx_t sctx = { .cb = cb, .userdata = userdata, .aborted = 0 };
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, stream_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sctx);

    apply_common_opts(curl, req, slist);

    CURLcode rc = curl_easy_perform(curl);

    int result = CLAWD_OK;
    if (sctx.aborted) {
        result = CLAWD_OK; /* user-initiated abort is not an error */
    } else if (rc != CURLE_OK) {
        if (rc == CURLE_OPERATION_TIMEDOUT)
            result = CLAWD_ERR_TIMEOUT;
        else
            result = CLAWD_ERR_NET;
    }

    curl_slist_free_all(slist);
    curl_easy_cleanup(curl);
    return result;
}

int clawd_http_sse(const clawd_http_request_t *req,
                   clawd_sse_cb cb, void *userdata)
{
    if (!req || !cb)
        return CLAWD_ERR_INVALID;

    CURL *curl = curl_easy_init();
    if (!curl)
        return CLAWD_ERR_INTERNAL;

    struct curl_slist *slist = headers_to_slist(req->headers);

    /* Add Accept header for SSE if not already present */
    bool has_accept = false;
    for (const clawd_http_header_t *h = req->headers; h; h = h->next) {
        if (strcasecmp(h->name, "Accept") == 0) {
            has_accept = true;
            break;
        }
    }
    if (!has_accept)
        slist = curl_slist_append(slist, "Accept: text/event-stream");

    sse_ctx_t sctx;
    sse_ctx_init(&sctx, cb, userdata);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, sse_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sctx);

    apply_common_opts(curl, req, slist);

    CURLcode rc = curl_easy_perform(curl);

    /* Flush any pending event at end of stream */
    if (!sctx.aborted && sctx.data_buf && sctx.data_len > 0)
        sse_dispatch(&sctx);

    int result = CLAWD_OK;
    if (sctx.aborted) {
        result = CLAWD_OK;
    } else if (rc != CURLE_OK && rc != CURLE_WRITE_ERROR) {
        if (rc == CURLE_OPERATION_TIMEDOUT)
            result = CLAWD_ERR_TIMEOUT;
        else
            result = CLAWD_ERR_NET;
    }

    sse_ctx_free(&sctx);
    curl_slist_free_all(slist);
    curl_easy_cleanup(curl);
    return result;
}

void clawd_http_response_free(clawd_http_response_t *resp)
{
    if (!resp)
        return;
    free(resp->body);
    free(resp->content_type);
    clawd_http_header_free(resp->headers);
    memset(resp, 0, sizeof(*resp));
}

int clawd_http_header_add(clawd_http_header_t **list,
                          const char *name, const char *value)
{
    if (!list || !name || !value)
        return -1;

    clawd_http_header_t *hdr = calloc(1, sizeof(*hdr));
    if (!hdr)
        return -1;

    hdr->name = strdup(name);
    hdr->value = strdup(value);
    if (!hdr->name || !hdr->value) {
        free(hdr->name);
        free(hdr->value);
        free(hdr);
        return -1;
    }

    hdr->next = *list;
    *list = hdr;
    return 0;
}

void clawd_http_header_free(clawd_http_header_t *list)
{
    while (list) {
        clawd_http_header_t *next = list->next;
        free(list->name);
        free(list->value);
        free(list);
        list = next;
    }
}

char *clawd_http_url_encode(const char *s)
{
    if (!s)
        return NULL;

    /*
     * Worst case: every character becomes %XX (3x expansion).
     * Pre-calculate the exact size to avoid reallocations.
     */
    size_t slen = strlen(s);
    size_t cap = 1; /* NUL */
    for (size_t i = 0; i < slen; i++) {
        unsigned char c = (unsigned char)s[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            cap += 1;
        else
            cap += 3;
    }

    char *out = malloc(cap);
    if (!out)
        return NULL;

    static const char hex[] = "0123456789ABCDEF";
    size_t pos = 0;
    for (size_t i = 0; i < slen; i++) {
        unsigned char c = (unsigned char)s[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out[pos++] = (char)c;
        } else {
            out[pos++] = '%';
            out[pos++] = hex[c >> 4];
            out[pos++] = hex[c & 0x0F];
        }
    }
    out[pos] = '\0';
    return out;
}
