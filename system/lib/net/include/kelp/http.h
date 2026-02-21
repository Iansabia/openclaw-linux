/*
 * kelp-linux :: libkelp-net
 * http.h - HTTP client (libcurl backend)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_HTTP_H
#define KELP_HTTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Header linked list ------------------------------------------------- */

typedef struct kelp_http_header {
    char *name;
    char *value;
    struct kelp_http_header *next;
} kelp_http_header_t;

/* ---- Response ----------------------------------------------------------- */

typedef struct kelp_http_response {
    int                  status_code;
    kelp_http_header_t *headers;
    uint8_t             *body;
    size_t               body_len;
    char                *content_type;
} kelp_http_response_t;

/* ---- Request ------------------------------------------------------------ */

typedef struct kelp_http_request {
    const char          *method;          /* GET, POST, PUT, DELETE, PATCH */
    const char          *url;
    kelp_http_header_t *headers;
    const void          *body;
    size_t               body_len;
    int                  timeout_ms;
    bool                 follow_redirects;
    const char          *ca_bundle;       /* optional custom CA bundle path */
} kelp_http_request_t;

/* ---- Streaming callback ------------------------------------------------- */

/**
 * Called for each chunk of response data during a streaming request.
 * Return 0 to continue, non-zero to abort.
 */
typedef int (*kelp_http_stream_cb)(const void *data, size_t len,
                                    void *userdata);

/* ---- Server-Sent Events ------------------------------------------------- */

typedef struct kelp_sse_event {
    const char *event;    /* event type (may be NULL) */
    const char *data;     /* event data */
    const char *id;       /* event id (may be NULL) */
} kelp_sse_event_t;

/**
 * Called for each Server-Sent Event.
 * Return 0 to continue, non-zero to abort.
 */
typedef int (*kelp_sse_cb)(const kelp_sse_event_t *event, void *userdata);

/* ---- API ---------------------------------------------------------------- */

/** Global initialization (calls curl_global_init). Call once at startup. */
int kelp_http_init(void);

/** Global cleanup (calls curl_global_cleanup). Call once at shutdown. */
void kelp_http_cleanup(void);

/**
 * Perform a synchronous HTTP request.
 * Returns KELP_OK on success, or an error code.
 */
int kelp_http_request(const kelp_http_request_t *req,
                       kelp_http_response_t *resp);

/**
 * Perform a streaming HTTP request.  The callback is invoked for each
 * chunk of response body data as it arrives.
 * Returns KELP_OK on success, or an error code.
 */
int kelp_http_stream(const kelp_http_request_t *req,
                      kelp_http_stream_cb cb, void *userdata);

/**
 * Perform an SSE (Server-Sent Events) streaming request.
 * The callback is invoked for each complete event.
 * Returns KELP_OK on success, or an error code.
 */
int kelp_http_sse(const kelp_http_request_t *req,
                   kelp_sse_cb cb, void *userdata);

/** Free all memory owned by a response struct. */
void kelp_http_response_free(kelp_http_response_t *resp);

/** Append a header to a linked list.  Returns 0 on success. */
int kelp_http_header_add(kelp_http_header_t **list,
                          const char *name, const char *value);

/** Free an entire header linked list. */
void kelp_http_header_free(kelp_http_header_t *list);

/**
 * URL-encode a string.
 * Returns a malloc'd NUL-terminated string.  The caller must free it.
 * Returns NULL on allocation failure.
 */
char *kelp_http_url_encode(const char *s);

#ifdef __cplusplus
}
#endif

#endif /* KELP_HTTP_H */
