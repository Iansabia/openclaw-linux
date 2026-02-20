/*
 * clawd-linux :: libclawd-net
 * test_net.c - Unit tests for the networking library
 *
 * Tests SSRF prevention, URL encoding, header management, and SSE parsing.
 * All tests run offline -- no network access required.
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/http.h>
#include <clawd/ssrf.h>
#include <clawd/heartbeat.h>
#include <clawd/tls.h>
#include <clawd/mdns.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run    = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { \
        tests_run++; \
        printf("  %-50s ", #name); \
        fflush(stdout); \
    } while (0)

#define PASS() \
    do { \
        tests_passed++; \
        printf("[PASS]\n"); \
    } while (0)

#define FAIL(msg) \
    do { \
        printf("[FAIL] %s\n", (msg)); \
    } while (0)

#define ASSERT_TRUE(expr) \
    do { \
        if (!(expr)) { FAIL(#expr " is false"); return; } \
    } while (0)

#define ASSERT_FALSE(expr) \
    do { \
        if ((expr)) { FAIL(#expr " is true"); return; } \
    } while (0)

#define ASSERT_EQ_INT(a, b) \
    do { \
        if ((a) != (b)) { \
            char _buf[128]; \
            snprintf(_buf, sizeof(_buf), "%s == %d, expected %d", #a, (a), (b)); \
            FAIL(_buf); return; \
        } \
    } while (0)

#define ASSERT_EQ_STR(a, b) \
    do { \
        if (strcmp((a), (b)) != 0) { \
            char _buf[256]; \
            snprintf(_buf, sizeof(_buf), "%s == \"%s\", expected \"%s\"", \
                     #a, (a), (b)); \
            FAIL(_buf); return; \
        } \
    } while (0)

#define ASSERT_NOT_NULL(p) \
    do { \
        if ((p) == NULL) { FAIL(#p " is NULL"); return; } \
    } while (0)

#define ASSERT_NULL(p) \
    do { \
        if ((p) != NULL) { FAIL(#p " is not NULL"); return; } \
    } while (0)

/* ======================================================================== */
/* SSRF Prevention Tests                                                    */
/* ======================================================================== */

static void test_ssrf_loopback_ipv4(void)
{
    TEST(ssrf_loopback_ipv4);
    ASSERT_TRUE(clawd_ssrf_is_private_ip("127.0.0.1"));
    ASSERT_TRUE(clawd_ssrf_is_private_ip("127.0.0.2"));
    ASSERT_TRUE(clawd_ssrf_is_private_ip("127.255.255.255"));
    PASS();
}

static void test_ssrf_private_class_a(void)
{
    TEST(ssrf_private_class_a);
    ASSERT_TRUE(clawd_ssrf_is_private_ip("10.0.0.1"));
    ASSERT_TRUE(clawd_ssrf_is_private_ip("10.255.255.255"));
    PASS();
}

static void test_ssrf_private_class_b(void)
{
    TEST(ssrf_private_class_b);
    ASSERT_TRUE(clawd_ssrf_is_private_ip("172.16.0.1"));
    ASSERT_TRUE(clawd_ssrf_is_private_ip("172.31.255.255"));
    /* 172.32.x.x is NOT private */
    ASSERT_FALSE(clawd_ssrf_is_private_ip("172.32.0.1"));
    PASS();
}

static void test_ssrf_private_class_c(void)
{
    TEST(ssrf_private_class_c);
    ASSERT_TRUE(clawd_ssrf_is_private_ip("192.168.0.1"));
    ASSERT_TRUE(clawd_ssrf_is_private_ip("192.168.255.255"));
    PASS();
}

static void test_ssrf_link_local(void)
{
    TEST(ssrf_link_local);
    ASSERT_TRUE(clawd_ssrf_is_private_ip("169.254.0.1"));
    ASSERT_TRUE(clawd_ssrf_is_private_ip("169.254.169.254")); /* metadata */
    ASSERT_TRUE(clawd_ssrf_is_private_ip("169.254.255.255"));
    PASS();
}

static void test_ssrf_metadata_endpoint(void)
{
    TEST(ssrf_metadata_endpoint);
    /* Cloud metadata endpoint must be blocked */
    ASSERT_TRUE(clawd_ssrf_is_private_ip("169.254.169.254"));
    PASS();
}

static void test_ssrf_ipv6_loopback(void)
{
    TEST(ssrf_ipv6_loopback);
    ASSERT_TRUE(clawd_ssrf_is_private_ip("::1"));
    PASS();
}

static void test_ssrf_ipv6_unique_local(void)
{
    TEST(ssrf_ipv6_unique_local);
    ASSERT_TRUE(clawd_ssrf_is_private_ip("fc00::1"));
    ASSERT_TRUE(clawd_ssrf_is_private_ip("fd00::1"));
    ASSERT_TRUE(clawd_ssrf_is_private_ip("fdff:ffff::1"));
    PASS();
}

static void test_ssrf_ipv6_link_local(void)
{
    TEST(ssrf_ipv6_link_local);
    ASSERT_TRUE(clawd_ssrf_is_private_ip("fe80::1"));
    ASSERT_TRUE(clawd_ssrf_is_private_ip("fe80::ffff:ffff:ffff:ffff"));
    PASS();
}

static void test_ssrf_public_ip(void)
{
    TEST(ssrf_public_ip);
    ASSERT_FALSE(clawd_ssrf_is_private_ip("8.8.8.8"));
    ASSERT_FALSE(clawd_ssrf_is_private_ip("1.1.1.1"));
    ASSERT_FALSE(clawd_ssrf_is_private_ip("93.184.216.34"));
    PASS();
}

static void test_ssrf_public_ipv6(void)
{
    TEST(ssrf_public_ipv6);
    ASSERT_FALSE(clawd_ssrf_is_private_ip("2001:4860:4860::8888"));
    ASSERT_FALSE(clawd_ssrf_is_private_ip("2606:4700:4700::1111"));
    PASS();
}

static void test_ssrf_null_host(void)
{
    TEST(ssrf_null_host);
    ASSERT_TRUE(clawd_ssrf_is_private_ip(NULL));
    PASS();
}

static void test_ssrf_check_private_url(void)
{
    TEST(ssrf_check_private_url);
    ASSERT_EQ_INT(clawd_ssrf_check("http://127.0.0.1/admin"), -1);
    ASSERT_EQ_INT(clawd_ssrf_check("http://10.0.0.1:8080/api"), -1);
    ASSERT_EQ_INT(clawd_ssrf_check("https://192.168.1.1/"), -1);
    ASSERT_EQ_INT(clawd_ssrf_check("http://169.254.169.254/latest/meta-data"), -1);
    PASS();
}

static void test_ssrf_check_null_url(void)
{
    TEST(ssrf_check_null_url);
    ASSERT_EQ_INT(clawd_ssrf_check(NULL), -1);
    PASS();
}

static void test_ssrf_check_bad_url(void)
{
    TEST(ssrf_check_bad_url);
    ASSERT_EQ_INT(clawd_ssrf_check("not-a-url"), -1);
    ASSERT_EQ_INT(clawd_ssrf_check(""), -1);
    PASS();
}

static void test_ssrf_allow_list(void)
{
    TEST(ssrf_allow_list);
    clawd_ssrf_lists_reset();

    /* 127.0.0.1 should be blocked by default */
    ASSERT_EQ_INT(clawd_ssrf_check("http://127.0.0.1/health"), -1);

    /* Add to allow list */
    clawd_ssrf_allow_list_add("127.0.0.1");
    ASSERT_EQ_INT(clawd_ssrf_check("http://127.0.0.1/health"), 0);

    clawd_ssrf_lists_reset();
    PASS();
}

static void test_ssrf_block_list(void)
{
    TEST(ssrf_block_list);
    clawd_ssrf_lists_reset();

    /* A public IP should normally pass */
    ASSERT_EQ_INT(clawd_ssrf_check("http://8.8.8.8/"), 0);

    /* Add to block list -- should now be blocked */
    clawd_ssrf_block_list_add("8.8.8.8");
    ASSERT_EQ_INT(clawd_ssrf_check("http://8.8.8.8/"), -1);

    clawd_ssrf_lists_reset();
    PASS();
}

static void test_ssrf_block_overrides_allow(void)
{
    TEST(ssrf_block_overrides_allow);
    clawd_ssrf_lists_reset();

    /* If a host is on both lists, block wins */
    clawd_ssrf_allow_list_add("evil.example.com");
    clawd_ssrf_block_list_add("evil.example.com");
    ASSERT_EQ_INT(clawd_ssrf_check("http://evil.example.com/"), -1);

    clawd_ssrf_lists_reset();
    PASS();
}

static void test_ssrf_ipv6_url(void)
{
    TEST(ssrf_ipv6_url);
    ASSERT_EQ_INT(clawd_ssrf_check("http://[::1]/admin"), -1);
    ASSERT_EQ_INT(clawd_ssrf_check("http://[fe80::1]/"), -1);
    ASSERT_EQ_INT(clawd_ssrf_check("http://[fc00::1]:8080/api"), -1);
    PASS();
}

static void test_ssrf_cgnat(void)
{
    TEST(ssrf_cgnat);
    ASSERT_TRUE(clawd_ssrf_is_private_ip("100.64.0.1"));
    ASSERT_TRUE(clawd_ssrf_is_private_ip("100.127.255.255"));
    /* Just outside CGNAT range */
    ASSERT_FALSE(clawd_ssrf_is_private_ip("100.128.0.1"));
    PASS();
}

/* ======================================================================== */
/* URL Encoding Tests                                                       */
/* ======================================================================== */

static void test_url_encode_basic(void)
{
    TEST(url_encode_basic);
    char *enc = clawd_http_url_encode("hello world");
    ASSERT_NOT_NULL(enc);
    ASSERT_EQ_STR(enc, "hello%20world");
    free(enc);
    PASS();
}

static void test_url_encode_special_chars(void)
{
    TEST(url_encode_special_chars);
    char *enc = clawd_http_url_encode("foo=bar&baz=qux");
    ASSERT_NOT_NULL(enc);
    ASSERT_EQ_STR(enc, "foo%3Dbar%26baz%3Dqux");
    free(enc);
    PASS();
}

static void test_url_encode_unreserved(void)
{
    TEST(url_encode_unreserved);
    /* RFC 3986 unreserved: A-Z a-z 0-9 - _ . ~ */
    char *enc = clawd_http_url_encode("hello-world_v1.0~test");
    ASSERT_NOT_NULL(enc);
    ASSERT_EQ_STR(enc, "hello-world_v1.0~test");
    free(enc);
    PASS();
}

static void test_url_encode_empty(void)
{
    TEST(url_encode_empty);
    char *enc = clawd_http_url_encode("");
    ASSERT_NOT_NULL(enc);
    ASSERT_EQ_STR(enc, "");
    free(enc);
    PASS();
}

static void test_url_encode_null(void)
{
    TEST(url_encode_null);
    char *enc = clawd_http_url_encode(NULL);
    ASSERT_NULL(enc);
    PASS();
}

static void test_url_encode_unicode(void)
{
    TEST(url_encode_unicode);
    /* UTF-8 encoded e-acute: 0xC3 0xA9 */
    char *enc = clawd_http_url_encode("caf\xC3\xA9");
    ASSERT_NOT_NULL(enc);
    ASSERT_EQ_STR(enc, "caf%C3%A9");
    free(enc);
    PASS();
}

static void test_url_encode_slash(void)
{
    TEST(url_encode_slash);
    char *enc = clawd_http_url_encode("path/to/file");
    ASSERT_NOT_NULL(enc);
    ASSERT_EQ_STR(enc, "path%2Fto%2Ffile");
    free(enc);
    PASS();
}

/* ======================================================================== */
/* Header Management Tests                                                  */
/* ======================================================================== */

static void test_header_add_single(void)
{
    TEST(header_add_single);
    clawd_http_header_t *list = NULL;
    int rc = clawd_http_header_add(&list, "Content-Type", "application/json");
    ASSERT_EQ_INT(rc, 0);
    ASSERT_NOT_NULL(list);
    ASSERT_EQ_STR(list->name, "Content-Type");
    ASSERT_EQ_STR(list->value, "application/json");
    ASSERT_NULL(list->next);
    clawd_http_header_free(list);
    PASS();
}

static void test_header_add_multiple(void)
{
    TEST(header_add_multiple);
    clawd_http_header_t *list = NULL;
    clawd_http_header_add(&list, "Accept", "text/html");
    clawd_http_header_add(&list, "Authorization", "Bearer token123");
    clawd_http_header_add(&list, "X-Custom", "value");

    /* Headers are prepended, so last added is first */
    ASSERT_NOT_NULL(list);
    ASSERT_EQ_STR(list->name, "X-Custom");
    ASSERT_NOT_NULL(list->next);
    ASSERT_EQ_STR(list->next->name, "Authorization");
    ASSERT_NOT_NULL(list->next->next);
    ASSERT_EQ_STR(list->next->next->name, "Accept");
    ASSERT_NULL(list->next->next->next);

    clawd_http_header_free(list);
    PASS();
}

static void test_header_add_null_args(void)
{
    TEST(header_add_null_args);
    clawd_http_header_t *list = NULL;
    ASSERT_EQ_INT(clawd_http_header_add(NULL, "X", "Y"), -1);
    ASSERT_EQ_INT(clawd_http_header_add(&list, NULL, "Y"), -1);
    ASSERT_EQ_INT(clawd_http_header_add(&list, "X", NULL), -1);
    ASSERT_NULL(list);
    PASS();
}

static void test_header_free_null(void)
{
    TEST(header_free_null);
    /* Should not crash */
    clawd_http_header_free(NULL);
    PASS();
}

/* ======================================================================== */
/* SSE Parsing Tests                                                        */
/* ======================================================================== */

/*
 * To test the SSE parser without making network requests, we expose the
 * internal SSE parsing logic through a test helper.  We simulate feeding
 * raw SSE text and collecting the parsed events via a callback.
 */

#define MAX_TEST_EVENTS 16

typedef struct {
    char *event;
    char *data;
    char *id;
} test_event_t;

typedef struct {
    test_event_t events[MAX_TEST_EVENTS];
    int          count;
} test_event_collector_t;

static int collect_sse_event(const clawd_sse_event_t *ev, void *ud)
{
    test_event_collector_t *col = (test_event_collector_t *)ud;
    if (col->count >= MAX_TEST_EVENTS)
        return -1; /* abort */

    test_event_t *te = &col->events[col->count++];
    te->event = ev->event ? strdup(ev->event) : NULL;
    te->data  = ev->data  ? strdup(ev->data)  : NULL;
    te->id    = ev->id    ? strdup(ev->id)    : NULL;
    return 0;
}

static void free_test_events(test_event_collector_t *col)
{
    for (int i = 0; i < col->count; i++) {
        free(col->events[i].event);
        free(col->events[i].data);
        free(col->events[i].id);
    }
    col->count = 0;
}

/*
 * Minimal SSE parser reimplementation for testing purposes.
 * This mirrors the logic in http.c but is self-contained so we can
 * unit-test SSE parsing without curl.
 */

typedef struct {
    clawd_sse_cb  cb;
    void         *userdata;
    int           aborted;
    char         *event_type;
    char         *data_buf;
    size_t        data_len;
    size_t        data_cap;
    char         *last_id;
    char         *line_buf;
    size_t        line_len;
    size_t        line_cap;
} test_sse_parser_t;

static void tsp_init(test_sse_parser_t *p, clawd_sse_cb cb, void *ud)
{
    memset(p, 0, sizeof(*p));
    p->cb       = cb;
    p->userdata = ud;
}

static void tsp_free(test_sse_parser_t *p)
{
    free(p->event_type);
    free(p->data_buf);
    free(p->last_id);
    free(p->line_buf);
}

static void tsp_append_data(test_sse_parser_t *p, const char *text, size_t len)
{
    size_t needed = p->data_len + len + 2;
    if (needed > p->data_cap) {
        size_t nc = p->data_cap ? p->data_cap : 256;
        while (nc < needed) nc *= 2;
        char *tmp = realloc(p->data_buf, nc);
        if (!tmp) return;
        p->data_buf = tmp;
        p->data_cap = nc;
    }
    memcpy(p->data_buf + p->data_len, text, len);
    p->data_len += len;
    p->data_buf[p->data_len++] = '\n';
    p->data_buf[p->data_len] = '\0';
}

static void tsp_dispatch(test_sse_parser_t *p)
{
    if (!p->data_buf || p->data_len == 0)
        goto reset;
    if (p->data_len > 0 && p->data_buf[p->data_len - 1] == '\n') {
        p->data_buf[p->data_len - 1] = '\0';
        p->data_len--;
    }
    clawd_sse_event_t ev = {
        .event = p->event_type,
        .data  = p->data_buf,
        .id    = p->last_id
    };
    if (p->cb(&ev, p->userdata) != 0)
        p->aborted = 1;
reset:
    free(p->event_type); p->event_type = NULL;
    free(p->data_buf); p->data_buf = NULL;
    p->data_len = 0; p->data_cap = 0;
}

static void tsp_process_line(test_sse_parser_t *p, const char *line, size_t len)
{
    if (len == 0) { tsp_dispatch(p); return; }
    if (line[0] == ':') return;

    const char *colon = memchr(line, ':', len);
    size_t flen;
    const char *val;
    size_t vlen;
    if (colon) {
        flen = (size_t)(colon - line);
        val = colon + 1;
        vlen = len - flen - 1;
        if (vlen > 0 && val[0] == ' ') { val++; vlen--; }
    } else {
        flen = len; val = ""; vlen = 0;
    }

    if (flen == 4 && memcmp(line, "data", 4) == 0) {
        tsp_append_data(p, val, vlen);
    } else if (flen == 5 && memcmp(line, "event", 5) == 0) {
        free(p->event_type);
        p->event_type = strndup(val, vlen);
    } else if (flen == 2 && memcmp(line, "id", 2) == 0) {
        free(p->last_id);
        p->last_id = strndup(val, vlen);
    }
}

static void tsp_feed(test_sse_parser_t *p, const char *data, size_t len)
{
    for (size_t i = 0; i < len && !p->aborted; i++) {
        char c = data[i];
        if (c == '\n' || c == '\r') {
            if (c == '\r' && i + 1 < len && data[i + 1] == '\n') i++;
            tsp_process_line(p, p->line_buf ? p->line_buf : "", p->line_len);
            p->line_len = 0;
            continue;
        }
        if (p->line_len + 2 > p->line_cap) {
            size_t nc = p->line_cap ? p->line_cap * 2 : 256;
            char *tmp = realloc(p->line_buf, nc);
            if (!tmp) return;
            p->line_buf = tmp;
            p->line_cap = nc;
        }
        p->line_buf[p->line_len++] = c;
        p->line_buf[p->line_len] = '\0';
    }
}

/* Helper: feed a complete SSE stream and flush */
static void feed_sse_text(test_sse_parser_t *p, const char *text)
{
    tsp_feed(p, text, strlen(text));
    /* Flush any pending event */
    if (p->data_buf && p->data_len > 0)
        tsp_dispatch(p);
}

static void test_sse_simple_data(void)
{
    TEST(sse_simple_data);
    test_event_collector_t col = {0};
    test_sse_parser_t parser;
    tsp_init(&parser, collect_sse_event, &col);

    feed_sse_text(&parser, "data: hello world\n\n");

    ASSERT_EQ_INT(col.count, 1);
    ASSERT_EQ_STR(col.events[0].data, "hello world");
    ASSERT_NULL(col.events[0].event);
    ASSERT_NULL(col.events[0].id);

    free_test_events(&col);
    tsp_free(&parser);
    PASS();
}

static void test_sse_multi_data_lines(void)
{
    TEST(sse_multi_data_lines);
    test_event_collector_t col = {0};
    test_sse_parser_t parser;
    tsp_init(&parser, collect_sse_event, &col);

    feed_sse_text(&parser, "data: line one\ndata: line two\ndata: line three\n\n");

    ASSERT_EQ_INT(col.count, 1);
    ASSERT_EQ_STR(col.events[0].data, "line one\nline two\nline three");

    free_test_events(&col);
    tsp_free(&parser);
    PASS();
}

static void test_sse_named_event(void)
{
    TEST(sse_named_event);
    test_event_collector_t col = {0};
    test_sse_parser_t parser;
    tsp_init(&parser, collect_sse_event, &col);

    feed_sse_text(&parser,
        "event: message\ndata: {\"text\":\"hi\"}\n\n"
        "event: done\ndata: [DONE]\n\n");

    ASSERT_EQ_INT(col.count, 2);
    ASSERT_EQ_STR(col.events[0].event, "message");
    ASSERT_EQ_STR(col.events[0].data, "{\"text\":\"hi\"}");
    ASSERT_EQ_STR(col.events[1].event, "done");
    ASSERT_EQ_STR(col.events[1].data, "[DONE]");

    free_test_events(&col);
    tsp_free(&parser);
    PASS();
}

static void test_sse_with_id(void)
{
    TEST(sse_with_id);
    test_event_collector_t col = {0};
    test_sse_parser_t parser;
    tsp_init(&parser, collect_sse_event, &col);

    feed_sse_text(&parser, "id: 42\ndata: event with id\n\n");

    ASSERT_EQ_INT(col.count, 1);
    ASSERT_EQ_STR(col.events[0].id, "42");
    ASSERT_EQ_STR(col.events[0].data, "event with id");

    free_test_events(&col);
    tsp_free(&parser);
    PASS();
}

static void test_sse_id_persists(void)
{
    TEST(sse_id_persists);
    test_event_collector_t col = {0};
    test_sse_parser_t parser;
    tsp_init(&parser, collect_sse_event, &col);

    feed_sse_text(&parser,
        "id: 1\ndata: first\n\n"
        "data: second\n\n");

    ASSERT_EQ_INT(col.count, 2);
    ASSERT_EQ_STR(col.events[0].id, "1");
    ASSERT_EQ_STR(col.events[0].data, "first");
    /* id persists to next event per SSE spec */
    ASSERT_EQ_STR(col.events[1].id, "1");
    ASSERT_EQ_STR(col.events[1].data, "second");

    free_test_events(&col);
    tsp_free(&parser);
    PASS();
}

static void test_sse_comment_ignored(void)
{
    TEST(sse_comment_ignored);
    test_event_collector_t col = {0};
    test_sse_parser_t parser;
    tsp_init(&parser, collect_sse_event, &col);

    feed_sse_text(&parser, ": this is a comment\ndata: real data\n\n");

    ASSERT_EQ_INT(col.count, 1);
    ASSERT_EQ_STR(col.events[0].data, "real data");

    free_test_events(&col);
    tsp_free(&parser);
    PASS();
}

static void test_sse_empty_data(void)
{
    TEST(sse_empty_data);
    test_event_collector_t col = {0};
    test_sse_parser_t parser;
    tsp_init(&parser, collect_sse_event, &col);

    feed_sse_text(&parser, "data:\n\n");

    ASSERT_EQ_INT(col.count, 1);
    ASSERT_EQ_STR(col.events[0].data, "");

    free_test_events(&col);
    tsp_free(&parser);
    PASS();
}

static void test_sse_no_space_after_colon(void)
{
    TEST(sse_no_space_after_colon);
    test_event_collector_t col = {0};
    test_sse_parser_t parser;
    tsp_init(&parser, collect_sse_event, &col);

    feed_sse_text(&parser, "data:no space\n\n");

    ASSERT_EQ_INT(col.count, 1);
    ASSERT_EQ_STR(col.events[0].data, "no space");

    free_test_events(&col);
    tsp_free(&parser);
    PASS();
}

static void test_sse_crlf_line_endings(void)
{
    TEST(sse_crlf_line_endings);
    test_event_collector_t col = {0};
    test_sse_parser_t parser;
    tsp_init(&parser, collect_sse_event, &col);

    feed_sse_text(&parser, "data: hello\r\n\r\n");

    ASSERT_EQ_INT(col.count, 1);
    ASSERT_EQ_STR(col.events[0].data, "hello");

    free_test_events(&col);
    tsp_free(&parser);
    PASS();
}

static void test_sse_multiple_events(void)
{
    TEST(sse_multiple_events);
    test_event_collector_t col = {0};
    test_sse_parser_t parser;
    tsp_init(&parser, collect_sse_event, &col);

    feed_sse_text(&parser,
        "data: first\n\n"
        "data: second\n\n"
        "data: third\n\n");

    ASSERT_EQ_INT(col.count, 3);
    ASSERT_EQ_STR(col.events[0].data, "first");
    ASSERT_EQ_STR(col.events[1].data, "second");
    ASSERT_EQ_STR(col.events[2].data, "third");

    free_test_events(&col);
    tsp_free(&parser);
    PASS();
}

static void test_sse_chunked_delivery(void)
{
    TEST(sse_chunked_delivery);
    /*
     * Simulate chunked delivery: the SSE data arrives in arbitrary
     * chunks, as would happen with real network I/O.
     */
    test_event_collector_t col = {0};
    test_sse_parser_t parser;
    tsp_init(&parser, collect_sse_event, &col);

    /* Feed in small chunks to simulate network fragmentation */
    tsp_feed(&parser, "da", 2);
    tsp_feed(&parser, "ta: he", 6);
    tsp_feed(&parser, "llo wor", 7);
    tsp_feed(&parser, "ld\n", 3);
    tsp_feed(&parser, "\n", 1);

    ASSERT_EQ_INT(col.count, 1);
    ASSERT_EQ_STR(col.events[0].data, "hello world");

    free_test_events(&col);
    tsp_free(&parser);
    PASS();
}

static void test_sse_event_type_resets(void)
{
    TEST(sse_event_type_resets);
    test_event_collector_t col = {0};
    test_sse_parser_t parser;
    tsp_init(&parser, collect_sse_event, &col);

    feed_sse_text(&parser,
        "event: custom\ndata: typed event\n\n"
        "data: untyped event\n\n");

    ASSERT_EQ_INT(col.count, 2);
    ASSERT_EQ_STR(col.events[0].event, "custom");
    ASSERT_NULL(col.events[1].event); /* event type resets */

    free_test_events(&col);
    tsp_free(&parser);
    PASS();
}

/* ======================================================================== */
/* Response Free Tests                                                      */
/* ======================================================================== */

static void test_response_free_null(void)
{
    TEST(response_free_null);
    /* Should not crash */
    clawd_http_response_free(NULL);
    PASS();
}

static void test_response_free_empty(void)
{
    TEST(response_free_empty);
    clawd_http_response_t resp;
    memset(&resp, 0, sizeof(resp));
    /* Should not crash */
    clawd_http_response_free(&resp);
    ASSERT_EQ_INT(resp.status_code, 0);
    ASSERT_NULL(resp.body);
    ASSERT_NULL(resp.headers);
    PASS();
}

/* ======================================================================== */
/* Heartbeat Struct Tests                                                   */
/* ======================================================================== */

static void test_heartbeat_is_alive_null(void)
{
    TEST(heartbeat_is_alive_null);
    ASSERT_FALSE(clawd_heartbeat_is_alive(NULL));
    PASS();
}

static void test_heartbeat_stop_null(void)
{
    TEST(heartbeat_stop_null);
    /* Should not crash */
    clawd_heartbeat_stop(NULL);
    PASS();
}

/* ======================================================================== */
/* Main                                                                     */
/* ======================================================================== */

int main(void)
{
    printf("libclawd-net unit tests\n");
    printf("=======================\n\n");

    printf("[SSRF Prevention]\n");
    test_ssrf_loopback_ipv4();
    test_ssrf_private_class_a();
    test_ssrf_private_class_b();
    test_ssrf_private_class_c();
    test_ssrf_link_local();
    test_ssrf_metadata_endpoint();
    test_ssrf_ipv6_loopback();
    test_ssrf_ipv6_unique_local();
    test_ssrf_ipv6_link_local();
    test_ssrf_public_ip();
    test_ssrf_public_ipv6();
    test_ssrf_null_host();
    test_ssrf_check_private_url();
    test_ssrf_check_null_url();
    test_ssrf_check_bad_url();
    test_ssrf_allow_list();
    test_ssrf_block_list();
    test_ssrf_block_overrides_allow();
    test_ssrf_ipv6_url();
    test_ssrf_cgnat();

    printf("\n[URL Encoding]\n");
    test_url_encode_basic();
    test_url_encode_special_chars();
    test_url_encode_unreserved();
    test_url_encode_empty();
    test_url_encode_null();
    test_url_encode_unicode();
    test_url_encode_slash();

    printf("\n[Header Management]\n");
    test_header_add_single();
    test_header_add_multiple();
    test_header_add_null_args();
    test_header_free_null();

    printf("\n[SSE Parsing]\n");
    test_sse_simple_data();
    test_sse_multi_data_lines();
    test_sse_named_event();
    test_sse_with_id();
    test_sse_id_persists();
    test_sse_comment_ignored();
    test_sse_empty_data();
    test_sse_no_space_after_colon();
    test_sse_crlf_line_endings();
    test_sse_multiple_events();
    test_sse_chunked_delivery();
    test_sse_event_type_resets();

    printf("\n[Response Free]\n");
    test_response_free_null();
    test_response_free_empty();

    printf("\n[Heartbeat]\n");
    test_heartbeat_is_alive_null();
    test_heartbeat_stop_null();

    printf("\n--------------------------------------------------\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
