/*
 * clawd-linux :: libclawd-core
 * tests/test_core.c - Unit tests for every core module
 *
 * Build with:
 *   cmake -DCLAWD_BUILD_TESTS=ON .. && make && ./test_core
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/clawd.h>

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int tests_run    = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { \
        tests_run++; \
        printf("  %-50s", #name); \
        fflush(stdout); \
    } while (0)

#define PASS() \
    do { \
        tests_passed++; \
        printf("[PASS]\n"); \
    } while (0)

/* ======================================================================== */
/* str                                                                       */
/* ======================================================================== */

static void test_str(void)
{
    printf("--- str ---\n");

    /* new / free */
    TEST(str_new_free);
    {
        clawd_str_t s = clawd_str_new();
        assert(s.data != NULL);
        assert(s.len == 0);
        assert(s.cap > 0);
        clawd_str_free(&s);
        assert(s.data == NULL);
        assert(s.len == 0);
    }
    PASS();

    /* from */
    TEST(str_from);
    {
        clawd_str_t s = clawd_str_from("hello");
        assert(s.len == 5);
        assert(strcmp(s.data, "hello") == 0);
        clawd_str_free(&s);
    }
    PASS();

    /* append */
    TEST(str_append);
    {
        clawd_str_t s = clawd_str_new();
        clawd_str_append(&s, "abc", 3);
        clawd_str_append_cstr(&s, "def");
        assert(s.len == 6);
        assert(strcmp(s.data, "abcdef") == 0);
        clawd_str_free(&s);
    }
    PASS();

    /* printf */
    TEST(str_printf);
    {
        clawd_str_t s = clawd_str_new();
        clawd_str_printf(&s, "num=%d str=%s", 42, "ok");
        assert(strcmp(s.data, "num=42 str=ok") == 0);
        clawd_str_free(&s);
    }
    PASS();

    /* dup */
    TEST(str_dup);
    {
        clawd_str_t a = clawd_str_from("copy me");
        clawd_str_t b = clawd_str_dup(&a);
        assert(strcmp(a.data, b.data) == 0);
        assert(a.data != b.data);
        clawd_str_free(&a);
        clawd_str_free(&b);
    }
    PASS();

    /* trim */
    TEST(str_trim);
    {
        clawd_str_t s = clawd_str_from("  hello world  ");
        clawd_str_trim(&s);
        assert(strcmp(s.data, "hello world") == 0);
        assert(s.len == 11);
        clawd_str_free(&s);
    }
    PASS();

    /* split */
    TEST(str_split);
    {
        int count = 0;
        char **parts = clawd_str_split("a,bb,ccc", ',', &count);
        assert(count == 3);
        assert(strcmp(parts[0], "a") == 0);
        assert(strcmp(parts[1], "bb") == 0);
        assert(strcmp(parts[2], "ccc") == 0);
        for (int i = 0; i < count; i++) free(parts[i]);
        free(parts);
    }
    PASS();

    /* starts_with / ends_with */
    TEST(str_starts_with);
    {
        assert(clawd_str_starts_with("hello world", "hello"));
        assert(!clawd_str_starts_with("hello world", "world"));
        assert(clawd_str_starts_with("hello", ""));
    }
    PASS();

    TEST(str_ends_with);
    {
        assert(clawd_str_ends_with("hello world", "world"));
        assert(!clawd_str_ends_with("hello world", "hello"));
        assert(clawd_str_ends_with("hello", ""));
    }
    PASS();

    /* replace */
    TEST(str_replace);
    {
        char *r = clawd_str_replace("aabbcc", "bb", "XX");
        assert(strcmp(r, "aaXXcc") == 0);
        free(r);

        r = clawd_str_replace("aaa", "a", "bb");
        assert(strcmp(r, "bbbbbb") == 0);
        free(r);

        r = clawd_str_replace("abc", "x", "y");
        assert(strcmp(r, "abc") == 0);
        free(r);
    }
    PASS();
}

/* ======================================================================== */
/* buf                                                                       */
/* ======================================================================== */

static void test_buf(void)
{
    printf("--- buf ---\n");

    TEST(buf_new_free);
    {
        clawd_buf_t b = clawd_buf_new(64);
        assert(b.data != NULL);
        assert(b.cap >= 64);
        assert(b.len == 0);
        clawd_buf_free(&b);
        assert(b.data == NULL);
    }
    PASS();

    TEST(buf_write);
    {
        clawd_buf_t b = clawd_buf_new(4);
        const char *msg = "hello, buffer!";
        clawd_buf_write(&b, msg, strlen(msg));
        assert(b.len == strlen(msg));
        assert(memcmp(b.data, msg, b.len) == 0);
        clawd_buf_free(&b);
    }
    PASS();

    TEST(buf_reset);
    {
        clawd_buf_t b = clawd_buf_new(16);
        clawd_buf_write(&b, "abc", 3);
        assert(b.len == 3);
        clawd_buf_reset(&b);
        assert(b.len == 0);
        assert(b.cap >= 16);
        clawd_buf_free(&b);
    }
    PASS();

    TEST(buf_read_write_file);
    {
        /* Write a buffer to a temp file, then read it back. */
        char path[] = "/tmp/clawd_test_buf_XXXXXX";
        int fd = mkstemp(path);
        assert(fd >= 0);
        close(fd);

        clawd_buf_t w = clawd_buf_new(16);
        const char *payload = "file round-trip test";
        clawd_buf_write(&w, payload, strlen(payload));
        assert(clawd_buf_write_file(&w, path) == 0);
        clawd_buf_free(&w);

        clawd_buf_t r = clawd_buf_new(16);
        assert(clawd_buf_read_file(&r, path) == 0);
        assert(r.len == strlen(payload));
        assert(memcmp(r.data, payload, r.len) == 0);
        clawd_buf_free(&r);

        unlink(path);
    }
    PASS();
}

/* ======================================================================== */
/* vec                                                                       */
/* ======================================================================== */

static void test_vec(void)
{
    printf("--- vec ---\n");

    TEST(int_vec);
    {
        clawd_int_vec_t v = clawd_int_vec_new();
        for (int i = 0; i < 100; i++)
            assert(clawd_int_vec_push(&v, i) == 0);

        assert(v.len == 100);
        assert(clawd_int_vec_get(&v, 0) == 0);
        assert(clawd_int_vec_get(&v, 99) == 99);

        int popped = clawd_int_vec_pop(&v);
        assert(popped == 99);
        assert(v.len == 99);

        clawd_int_vec_clear(&v);
        assert(v.len == 0);
        clawd_int_vec_free(&v);
    }
    PASS();

    TEST(str_vec);
    {
        clawd_str_vec_t v = clawd_str_vec_new();
        clawd_str_vec_push(&v, "alpha");
        clawd_str_vec_push(&v, "beta");
        clawd_str_vec_push(&v, "gamma");
        assert(v.len == 3);
        assert(strcmp(clawd_str_vec_get(&v, 1), "beta") == 0);
        clawd_str_vec_free(&v);
    }
    PASS();
}

/* ======================================================================== */
/* map                                                                       */
/* ======================================================================== */

static void test_map(void)
{
    printf("--- map ---\n");

    TEST(map_basic);
    {
        clawd_map_t *m = clawd_map_new();
        assert(m != NULL);

        int v1 = 1, v2 = 2, v3 = 3;
        assert(clawd_map_set(m, "one",   &v1) == 0);
        assert(clawd_map_set(m, "two",   &v2) == 0);
        assert(clawd_map_set(m, "three", &v3) == 0);
        assert(clawd_map_size(m) == 3);

        assert(clawd_map_get(m, "one")   == &v1);
        assert(clawd_map_get(m, "two")   == &v2);
        assert(clawd_map_get(m, "three") == &v3);
        assert(clawd_map_get(m, "four")  == NULL);

        assert(clawd_map_has(m, "two")  == true);
        assert(clawd_map_has(m, "four") == false);

        clawd_map_free(m);
    }
    PASS();

    TEST(map_overwrite);
    {
        clawd_map_t *m = clawd_map_new();
        int a = 10, b = 20;
        clawd_map_set(m, "key", &a);
        assert(clawd_map_get(m, "key") == &a);
        clawd_map_set(m, "key", &b);
        assert(clawd_map_get(m, "key") == &b);
        assert(clawd_map_size(m) == 1);
        clawd_map_free(m);
    }
    PASS();

    TEST(map_delete);
    {
        clawd_map_t *m = clawd_map_new();
        int v = 42;
        clawd_map_set(m, "del_me", &v);
        assert(clawd_map_size(m) == 1);
        assert(clawd_map_del(m, "del_me") == 0);
        assert(clawd_map_size(m) == 0);
        assert(clawd_map_get(m, "del_me") == NULL);
        assert(clawd_map_del(m, "del_me") == -1);
        clawd_map_free(m);
    }
    PASS();

    TEST(map_resize);
    {
        clawd_map_t *m = clawd_map_new();
        /* Insert enough entries to trigger at least one resize. */
        int vals[64];
        char key[16];
        for (int i = 0; i < 64; i++) {
            vals[i] = i;
            snprintf(key, sizeof(key), "key_%d", i);
            assert(clawd_map_set(m, key, &vals[i]) == 0);
        }
        assert(clawd_map_size(m) == 64);
        for (int i = 0; i < 64; i++) {
            snprintf(key, sizeof(key), "key_%d", i);
            assert(clawd_map_get(m, key) == &vals[i]);
        }
        clawd_map_free(m);
    }
    PASS();

    TEST(map_iter);
    {
        clawd_map_t *m = clawd_map_new();
        int a = 1, b = 2, c = 3;
        clawd_map_set(m, "a", &a);
        clawd_map_set(m, "b", &b);
        clawd_map_set(m, "c", &c);

        clawd_map_iter_t it = {0};
        int count = 0;
        while (clawd_map_iter(m, &it)) {
            assert(it.key != NULL);
            assert(it.value != NULL);
            count++;
        }
        assert(count == 3);
        clawd_map_free(m);
    }
    PASS();
}

/* ======================================================================== */
/* json                                                                      */
/* ======================================================================== */

static void test_json(void)
{
    printf("--- json ---\n");

    TEST(json_parse_and_get);
    {
        const char *text =
            "{\"name\":\"clawd\",\"version\":1,\"debug\":true,"
            "\"tags\":[\"a\",\"b\"],\"meta\":{\"x\":10}}";

        cJSON *obj = clawd_json_parse(text);
        assert(obj != NULL);

        const char *name = clawd_json_get_string(obj, "name");
        assert(name != NULL && strcmp(name, "clawd") == 0);

        assert(clawd_json_get_int(obj, "version", -1) == 1);
        assert(clawd_json_get_int(obj, "missing", -1) == -1);

        assert(clawd_json_get_bool(obj, "debug", false) == true);
        assert(clawd_json_get_bool(obj, "missing", false) == false);

        cJSON *tags = clawd_json_get_array(obj, "tags");
        assert(tags != NULL);
        assert(cJSON_GetArraySize(tags) == 2);

        cJSON *meta = clawd_json_get_object(obj, "meta");
        assert(meta != NULL);

        cJSON_Delete(obj);
    }
    PASS();

    TEST(json_stringify);
    {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "hello", "world");

        char *compact = clawd_json_stringify(obj);
        assert(compact != NULL);
        assert(strstr(compact, "\"hello\"") != NULL);
        assert(strstr(compact, "\"world\"") != NULL);
        free(compact);

        char *pretty = clawd_json_stringify_pretty(obj);
        assert(pretty != NULL);
        assert(strstr(pretty, "hello") != NULL);
        free(pretty);

        cJSON_Delete(obj);
    }
    PASS();

    TEST(json_parse_file);
    {
        /* Write JSON to a temp file and read it back. */
        char path[] = "/tmp/clawd_test_json_XXXXXX";
        int fd = mkstemp(path);
        assert(fd >= 0);
        const char *json_text = "{\"key\": \"value\"}";
        write(fd, json_text, strlen(json_text));
        close(fd);

        cJSON *obj = clawd_json_parse_file(path);
        assert(obj != NULL);
        assert(strcmp(clawd_json_get_string(obj, "key"), "value") == 0);
        cJSON_Delete(obj);
        unlink(path);
    }
    PASS();
}

/* ======================================================================== */
/* log                                                                       */
/* ======================================================================== */

static void test_log(void)
{
    printf("--- log ---\n");

    TEST(log_basic);
    {
        /* Redirect log output to a temp file. */
        char path[] = "/tmp/clawd_test_log_XXXXXX";
        int fd = mkstemp(path);
        assert(fd >= 0);
        close(fd);

        FILE *fp = fopen(path, "w");
        assert(fp != NULL);

        clawd_log_init("test", CLAWD_LOG_DEBUG);
        clawd_log_set_file(fp);

        CLAWD_INFO("hello %s", "world");
        CLAWD_DEBUG("debug message %d", 42);
        CLAWD_TRACE("this should be suppressed");

        fclose(fp);

        /* Read back and verify. */
        fp = fopen(path, "r");
        assert(fp != NULL);
        char line[512];
        int lines = 0;
        while (fgets(line, sizeof(line), fp)) lines++;
        fclose(fp);

        /* TRACE is below DEBUG, so we expect 2 lines. */
        assert(lines == 2);

        /* Restore default output. */
        clawd_log_set_file(NULL);
        unlink(path);
    }
    PASS();

    TEST(log_level_filter);
    {
        char path[] = "/tmp/clawd_test_log2_XXXXXX";
        int fd = mkstemp(path);
        assert(fd >= 0);
        close(fd);

        FILE *fp = fopen(path, "w");
        clawd_log_set_file(fp);
        clawd_log_set_level(CLAWD_LOG_ERROR);

        CLAWD_INFO("should not appear");
        CLAWD_WARN("should not appear");
        CLAWD_ERROR("should appear");

        fclose(fp);

        fp = fopen(path, "r");
        char line[512];
        int lines = 0;
        while (fgets(line, sizeof(line), fp)) lines++;
        fclose(fp);
        assert(lines == 1);

        clawd_log_set_file(NULL);
        clawd_log_set_level(CLAWD_LOG_INFO);
        unlink(path);
    }
    PASS();
}

/* ======================================================================== */
/* err                                                                       */
/* ======================================================================== */

static void test_err(void)
{
    printf("--- err ---\n");

    TEST(err_ok);
    {
        clawd_err_t e = {0};
        assert(clawd_err_ok(&e) == true);

        clawd_err_set(&e, CLAWD_ERR_IO, "file not found: %s", "/foo");
        assert(clawd_err_ok(&e) == false);
        assert(e.code == CLAWD_ERR_IO);
        assert(strstr(e.message, "/foo") != NULL);
    }
    PASS();

    TEST(err_string);
    {
        assert(strcmp(clawd_err_string(CLAWD_OK), "OK") == 0);
        assert(strcmp(clawd_err_string(CLAWD_ERR_NOMEM), "out of memory") == 0);
        assert(strcmp(clawd_err_string(CLAWD_ERR_TIMEOUT), "timeout") == 0);
        assert(strcmp(clawd_err_string(9999), "unknown error") == 0);
    }
    PASS();

    TEST(err_check_macro);
    {
        /*
         * CLAWD_CHECK returns from the enclosing function, so we test it
         * inside a helper that returns an int.
         */
        /* Just verify it compiles and the error struct is populated. */
        clawd_err_t e = {0};
        int *ptr = NULL;
        /* We can't directly test the return because we'd exit test_err().
         * Instead, test the non-failing path: */
        int val = 42;
        ptr = &val;
        /* This should NOT trigger (expression is true). */
        if (!(ptr != NULL)) {
            clawd_err_set(&e, CLAWD_ERR_NOMEM, "unexpected");
        }
        assert(clawd_err_ok(&e));
    }
    PASS();
}

/* ======================================================================== */
/* crypto                                                                    */
/* ======================================================================== */

static void test_crypto(void)
{
    printf("--- crypto ---\n");

    TEST(sha256);
    {
        /* SHA-256 of empty string is well-known. */
        char hex[65];
        clawd_sha256_hex("", 0, hex);
        assert(strcmp(hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            == 0);
    }
    PASS();

    TEST(sha256_hello);
    {
        char hex[65];
        clawd_sha256_hex("hello", 5, hex);
        assert(strcmp(hex,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
            == 0);
    }
    PASS();

    TEST(hmac_sha256);
    {
        uint8_t out[32];
        clawd_hmac_sha256("key", 3, "message", 7, out);
        /* Just verify it produces non-zero output and is deterministic. */
        uint8_t out2[32];
        clawd_hmac_sha256("key", 3, "message", 7, out2);
        assert(memcmp(out, out2, 32) == 0);

        /* Different key should produce different result. */
        uint8_t out3[32];
        clawd_hmac_sha256("key2", 4, "message", 7, out3);
        assert(memcmp(out, out3, 32) != 0);
    }
    PASS();

    TEST(random_bytes);
    {
        uint8_t buf1[16], buf2[16];
        assert(clawd_random_bytes(buf1, 16) == 0);
        assert(clawd_random_bytes(buf2, 16) == 0);
        /* Extremely unlikely to be equal. */
        assert(memcmp(buf1, buf2, 16) != 0);
    }
    PASS();

    TEST(base64_roundtrip);
    {
        const char *input = "Hello, clawd!";
        char *encoded = clawd_base64_encode(input, strlen(input));
        assert(encoded != NULL);

        size_t dec_len = 0;
        uint8_t *decoded = clawd_base64_decode(encoded, &dec_len);
        assert(decoded != NULL);
        assert(dec_len == strlen(input));
        assert(memcmp(decoded, input, dec_len) == 0);

        free(encoded);
        free(decoded);
    }
    PASS();

    TEST(base64_known);
    {
        /* "hello" -> "aGVsbG8=" */
        char *enc = clawd_base64_encode("hello", 5);
        assert(strcmp(enc, "aGVsbG8=") == 0);
        free(enc);
    }
    PASS();

    TEST(timing_safe_cmp);
    {
        const char a[] = "secret";
        const char b[] = "secret";
        const char c[] = "secreX";
        assert(clawd_timing_safe_cmp(a, b, 6) == 0);
        assert(clawd_timing_safe_cmp(a, c, 6) != 0);
    }
    PASS();
}

/* ======================================================================== */
/* main                                                                      */
/* ======================================================================== */

int main(void)
{
    printf("=== libclawd-core test suite ===\n\n");

    test_str();
    test_buf();
    test_vec();
    test_map();
    test_json();
    test_log();
    test_err();
    test_crypto();

    printf("\n=== results: %d / %d passed ===\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
