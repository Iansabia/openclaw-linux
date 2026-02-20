/*
 * clawd-linux :: libclawd-security
 * test_security.c - Unit tests for the security library
 *
 * Assert-based tests covering:
 *   - Path traversal detection (clawd_fs_is_safe_path)
 *   - Safe path resolution (clawd_fs_resolve_safe)
 *   - Filesystem permission checks (clawd_fs_check_perm, clawd_fs_check_ownership)
 *   - Policy rule matching (clawd_policy_check)
 *   - Path scanner patterns (clawd_path_scanner_check)
 *   - Audit event formatting (clawd_audit_log)
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <clawd/audit.h>
#include <clawd/fs_perm.h>
#include <clawd/policy.h>
#include <clawd/path_scan.h>
#include <clawd/timing.h>

/* ---- helpers ------------------------------------------------------------ */

static int test_count   = 0;
static int pass_count   = 0;
static int fail_count   = 0;

#define TEST_BEGIN(name) \
    do { \
        test_count++; \
        const char *_test_name = (name); \
        fprintf(stderr, "  [TEST] %s ... ", _test_name); \
        (void)_test_name; \
        int _test_passed = 1;

#define TEST_END() \
        if (_test_passed) { \
            pass_count++; \
            fprintf(stderr, "PASS\n"); \
        } \
    } while (0)

#define TEST_ASSERT(expr) \
    if (_test_passed && !(expr)) { \
        fail_count++; \
        _test_passed = 0; \
        fprintf(stderr, "FAIL (line %d: %s)\n", __LINE__, #expr); \
    }

/* ---- path traversal tests ----------------------------------------------- */

static void test_path_traversal(void)
{
    fprintf(stderr, "\n=== Path Traversal Detection ===\n");

    TEST_BEGIN("simple safe path") {
        TEST_ASSERT(clawd_fs_is_safe_path("/home/user/documents/file.txt"));
    } TEST_END();

    TEST_BEGIN("relative safe path") {
        TEST_ASSERT(clawd_fs_is_safe_path("foo/bar/baz.c"));
    } TEST_END();

    TEST_BEGIN("single dot in path is safe") {
        TEST_ASSERT(clawd_fs_is_safe_path("./foo/bar"));
    } TEST_END();

    TEST_BEGIN("simple traversal attack") {
        TEST_ASSERT(!clawd_fs_is_safe_path("../../../etc/passwd"));
    } TEST_END();

    TEST_BEGIN("traversal hidden in middle") {
        /* foo/../../ goes above foo's parent */
        TEST_ASSERT(!clawd_fs_is_safe_path("foo/../../secret"));
    } TEST_END();

    TEST_BEGIN("deeply nested traversal") {
        TEST_ASSERT(!clawd_fs_is_safe_path("a/b/c/../../../../etc/shadow"));
    } TEST_END();

    TEST_BEGIN("null path is unsafe") {
        TEST_ASSERT(!clawd_fs_is_safe_path(NULL));
    } TEST_END();

    TEST_BEGIN("empty path is unsafe") {
        TEST_ASSERT(!clawd_fs_is_safe_path(""));
    } TEST_END();

    TEST_BEGIN("root path is safe") {
        TEST_ASSERT(clawd_fs_is_safe_path("/"));
    } TEST_END();

    TEST_BEGIN("traversal at start of absolute path") {
        /* /.. would go above root -- but on a real FS /.. == / so depth
         * does not go negative.  However our checker sees "/.." and depth
         * goes 0 -> -1 which is caught. */
        TEST_ASSERT(!clawd_fs_is_safe_path("/.."));
    } TEST_END();
}

/* ---- safe resolution tests ---------------------------------------------- */

static void test_safe_resolution(void)
{
    fprintf(stderr, "\n=== Safe Path Resolution ===\n");

    TEST_BEGIN("resolve simple relative path") {
        char out[PATH_MAX];
        int rc = clawd_fs_resolve_safe("/tmp", "foo.txt", out, sizeof(out));
        /* This might fail if /tmp/foo.txt doesn't exist (ENOENT path). */
        /* We mostly just verify it doesn't crash and handles input. */
        (void)rc;
        /* At minimum it should not return an escape path. */
    } TEST_END();

    TEST_BEGIN("reject absolute relative path") {
        char out[PATH_MAX];
        int rc = clawd_fs_resolve_safe("/tmp", "/etc/passwd", out, sizeof(out));
        TEST_ASSERT(rc == -1);
    } TEST_END();

    TEST_BEGIN("reject traversal in relative") {
        char out[PATH_MAX];
        int rc = clawd_fs_resolve_safe("/tmp", "../etc/passwd", out, sizeof(out));
        TEST_ASSERT(rc == -1);
    } TEST_END();

    TEST_BEGIN("reject null base") {
        char out[PATH_MAX];
        int rc = clawd_fs_resolve_safe(NULL, "foo.txt", out, sizeof(out));
        TEST_ASSERT(rc == -1);
    } TEST_END();

    TEST_BEGIN("reject relative base") {
        char out[PATH_MAX];
        int rc = clawd_fs_resolve_safe("relative/base", "foo.txt",
                                       out, sizeof(out));
        TEST_ASSERT(rc == -1);
    } TEST_END();
}

/* ---- filesystem permission tests ---------------------------------------- */

static void test_fs_permissions(void)
{
    fprintf(stderr, "\n=== Filesystem Permission Checks ===\n");

    TEST_BEGIN("check read permission on /tmp") {
        int rc = clawd_fs_check_perm("/tmp", CLAWD_PERM_READ);
        TEST_ASSERT(rc == 0);
    } TEST_END();

    TEST_BEGIN("check nonexistent path") {
        int rc = clawd_fs_check_perm("/nonexistent_path_xyzzy_12345",
                                     CLAWD_PERM_READ);
        TEST_ASSERT(rc == -1);
    } TEST_END();

    TEST_BEGIN("check ownership of /tmp") {
        /* We just check it returns a boolean without crashing. */
        bool owned = clawd_fs_check_ownership("/tmp", getuid());
        /* /tmp is usually owned by root(0), not current user (unless root). */
        if (getuid() == 0) {
            TEST_ASSERT(owned);
        }
        /* Non-root: we just verify the function runs without error. */
    } TEST_END();

    TEST_BEGIN("check ownership of null path") {
        bool owned = clawd_fs_check_ownership(NULL, 0);
        TEST_ASSERT(!owned);
    } TEST_END();

    TEST_BEGIN("check null path perm") {
        int rc = clawd_fs_check_perm(NULL, CLAWD_PERM_READ);
        TEST_ASSERT(rc == -1);
    } TEST_END();
}

/* ---- policy rule matching tests ----------------------------------------- */

static void test_policy(void)
{
    fprintf(stderr, "\n=== Policy Rule Matching ===\n");

    TEST_BEGIN("empty policy allows everything") {
        clawd_policy_t *p = clawd_policy_new();
        TEST_ASSERT(p != NULL);

        clawd_policy_action_t a = clawd_policy_check(p, "bash", "ls -la");
        TEST_ASSERT(a == CLAWD_POLICY_ALLOW);

        clawd_policy_free(p);
    } TEST_END();

    TEST_BEGIN("explicit deny rule") {
        clawd_policy_t *p = clawd_policy_new();
        TEST_ASSERT(p != NULL);

        clawd_policy_rule_t rule = {
            .tool_name = "bash",
            .pattern   = "rm -rf /*",
            .action    = CLAWD_POLICY_DENY,
            .reason    = "dangerous",
        };
        int rc = clawd_policy_add_rule(p, &rule);
        TEST_ASSERT(rc == 0);

        clawd_policy_action_t a = clawd_policy_check(p, "bash", "rm -rf /home");
        TEST_ASSERT(a == CLAWD_POLICY_DENY);

        /* Non-matching command should be allowed. */
        a = clawd_policy_check(p, "bash", "echo hello");
        TEST_ASSERT(a == CLAWD_POLICY_ALLOW);

        clawd_policy_free(p);
    } TEST_END();

    TEST_BEGIN("wildcard tool name") {
        clawd_policy_t *p = clawd_policy_new();
        TEST_ASSERT(p != NULL);

        clawd_policy_rule_t rule = {
            .tool_name = "*",
            .pattern   = "*.env",
            .action    = CLAWD_POLICY_DENY,
            .reason    = "secret file",
        };
        clawd_policy_add_rule(p, &rule);

        TEST_ASSERT(clawd_policy_check(p, "file_read", ".env") ==
                    CLAWD_POLICY_DENY);
        TEST_ASSERT(clawd_policy_check(p, "file_write", "prod.env") ==
                    CLAWD_POLICY_DENY);
        TEST_ASSERT(clawd_policy_check(p, "bash", "cat config.yaml") ==
                    CLAWD_POLICY_ALLOW);

        clawd_policy_free(p);
    } TEST_END();

    TEST_BEGIN("first match wins") {
        clawd_policy_t *p = clawd_policy_new();
        TEST_ASSERT(p != NULL);

        /* First rule: allow bash "echo *" */
        clawd_policy_rule_t r1 = {
            .tool_name = "bash",
            .pattern   = "echo *",
            .action    = CLAWD_POLICY_ALLOW,
            .reason    = "echo is safe",
        };
        clawd_policy_add_rule(p, &r1);

        /* Second rule: audit all bash. */
        clawd_policy_rule_t r2 = {
            .tool_name = "bash",
            .pattern   = "*",
            .action    = CLAWD_POLICY_AUDIT,
            .reason    = "audit all",
        };
        clawd_policy_add_rule(p, &r2);

        /* "echo hello" should match rule 1 (allow), not rule 2 (audit). */
        TEST_ASSERT(clawd_policy_check(p, "bash", "echo hello") ==
                    CLAWD_POLICY_ALLOW);

        /* "ls" should match rule 2 (audit). */
        TEST_ASSERT(clawd_policy_check(p, "bash", "ls") ==
                    CLAWD_POLICY_AUDIT);

        clawd_policy_free(p);
    } TEST_END();

    TEST_BEGIN("default rules include deny for rm -rf /") {
        clawd_policy_t *p = clawd_policy_new();
        TEST_ASSERT(p != NULL);

        clawd_policy_add_default_rules(p);

        TEST_ASSERT(clawd_policy_check(p, "bash", "rm -rf /home") ==
                    CLAWD_POLICY_DENY);

        clawd_policy_free(p);
    } TEST_END();

    TEST_BEGIN("default rules deny writing to /etc") {
        clawd_policy_t *p = clawd_policy_new();
        TEST_ASSERT(p != NULL);

        clawd_policy_add_default_rules(p);

        TEST_ASSERT(clawd_policy_check(p, "file_write", "/etc/passwd") ==
                    CLAWD_POLICY_DENY);

        clawd_policy_free(p);
    } TEST_END();

    TEST_BEGIN("default rules audit bash commands") {
        clawd_policy_t *p = clawd_policy_new();
        TEST_ASSERT(p != NULL);

        clawd_policy_add_default_rules(p);

        /* A normal command that doesn't match deny rules should be audited. */
        TEST_ASSERT(clawd_policy_check(p, "bash", "ls -la /home") ==
                    CLAWD_POLICY_AUDIT);

        clawd_policy_free(p);
    } TEST_END();

    TEST_BEGIN("ask action") {
        clawd_policy_t *p = clawd_policy_new();
        TEST_ASSERT(p != NULL);

        clawd_policy_rule_t rule = {
            .tool_name = "bash",
            .pattern   = "sudo *",
            .action    = CLAWD_POLICY_ASK,
            .reason    = "privilege escalation requires confirmation",
        };
        clawd_policy_add_rule(p, &rule);

        TEST_ASSERT(clawd_policy_check(p, "bash", "sudo apt install foo") ==
                    CLAWD_POLICY_ASK);

        clawd_policy_free(p);
    } TEST_END();

    TEST_BEGIN("null policy check") {
        TEST_ASSERT(clawd_policy_check(NULL, "bash", "ls") ==
                    CLAWD_POLICY_ALLOW);
    } TEST_END();
}

/* ---- path scanner tests ------------------------------------------------- */

static void test_path_scanner(void)
{
    fprintf(stderr, "\n=== Path Scanner Patterns ===\n");

    TEST_BEGIN("empty scanner allows everything") {
        clawd_path_scanner_t *s = clawd_path_scanner_new();
        TEST_ASSERT(s != NULL);

        TEST_ASSERT(clawd_path_scanner_check(s, "/home/user/file.txt"));
        TEST_ASSERT(clawd_path_scanner_check(s, "/etc/passwd"));

        clawd_path_scanner_free(s);
    } TEST_END();

    TEST_BEGIN("deny .env files") {
        clawd_path_scanner_t *s = clawd_path_scanner_new();
        TEST_ASSERT(s != NULL);

        clawd_path_scanner_add_pattern(s, "*.env", true);

        TEST_ASSERT(!clawd_path_scanner_check(s, "/app/.env"));
        TEST_ASSERT(!clawd_path_scanner_check(s, "/app/production.env"));
        TEST_ASSERT(clawd_path_scanner_check(s, "/app/config.yaml"));

        clawd_path_scanner_free(s);
    } TEST_END();

    TEST_BEGIN("deny .ssh paths") {
        clawd_path_scanner_t *s = clawd_path_scanner_new();
        TEST_ASSERT(s != NULL);

        clawd_path_scanner_add_pattern(s, ".ssh/*", true);

        TEST_ASSERT(!clawd_path_scanner_check(s, ".ssh/id_rsa"));
        TEST_ASSERT(!clawd_path_scanner_check(s, ".ssh/config"));
        TEST_ASSERT(clawd_path_scanner_check(s, "/home/user/doc.txt"));

        clawd_path_scanner_free(s);
    } TEST_END();

    TEST_BEGIN("deny key files") {
        clawd_path_scanner_t *s = clawd_path_scanner_new();
        TEST_ASSERT(s != NULL);

        clawd_path_scanner_add_pattern(s, "*.pem", true);
        clawd_path_scanner_add_pattern(s, "*.key", true);

        TEST_ASSERT(!clawd_path_scanner_check(s, "/certs/server.pem"));
        TEST_ASSERT(!clawd_path_scanner_check(s, "/certs/server.key"));
        TEST_ASSERT(clawd_path_scanner_check(s, "/certs/server.crt"));

        clawd_path_scanner_free(s);
    } TEST_END();

    TEST_BEGIN("deny /proc and /sys") {
        clawd_path_scanner_t *s = clawd_path_scanner_new();
        TEST_ASSERT(s != NULL);

        clawd_path_scanner_add_pattern(s, "/proc/*", true);
        clawd_path_scanner_add_pattern(s, "/sys/*",  true);

        TEST_ASSERT(!clawd_path_scanner_check(s, "/proc/self/maps"));
        TEST_ASSERT(!clawd_path_scanner_check(s, "/sys/class/net"));
        TEST_ASSERT(clawd_path_scanner_check(s, "/var/log/syslog"));

        clawd_path_scanner_free(s);
    } TEST_END();

    TEST_BEGIN("first match wins (allow overrides later deny)") {
        clawd_path_scanner_t *s = clawd_path_scanner_new();
        TEST_ASSERT(s != NULL);

        /* Allow .env.example first. */
        clawd_path_scanner_add_pattern(s, "*.env.example", false);
        /* Then deny all .env. */
        clawd_path_scanner_add_pattern(s, "*.env", true);

        /* .env.example should be allowed (first rule matches). */
        TEST_ASSERT(clawd_path_scanner_check(s, "/app/.env.example"));
        /* .env should be denied (second rule matches). */
        TEST_ASSERT(!clawd_path_scanner_check(s, "/app/.env"));

        clawd_path_scanner_free(s);
    } TEST_END();

    TEST_BEGIN("default patterns deny sensitive files") {
        clawd_path_scanner_t *s = clawd_path_scanner_new();
        TEST_ASSERT(s != NULL);

        clawd_path_scanner_add_defaults(s);

        /* These should all be denied. */
        TEST_ASSERT(!clawd_path_scanner_check(s, "/app/.env"));
        TEST_ASSERT(!clawd_path_scanner_check(s, "/app/prod.env"));
        TEST_ASSERT(!clawd_path_scanner_check(s, "/home/user/.ssh/id_rsa"));
        TEST_ASSERT(!clawd_path_scanner_check(s, "/certs/ca.pem"));
        TEST_ASSERT(!clawd_path_scanner_check(s, "/certs/server.key"));
        TEST_ASSERT(!clawd_path_scanner_check(s, "/proc/self/environ"));
        TEST_ASSERT(!clawd_path_scanner_check(s, "/sys/class/net/eth0"));

        /* These should be allowed. */
        TEST_ASSERT(clawd_path_scanner_check(s, "/home/user/code/main.c"));
        TEST_ASSERT(clawd_path_scanner_check(s, "/var/log/syslog"));
        TEST_ASSERT(clawd_path_scanner_check(s, "/home/user/README.md"));

        clawd_path_scanner_free(s);
    } TEST_END();

    TEST_BEGIN("null path is denied") {
        clawd_path_scanner_t *s = clawd_path_scanner_new();
        TEST_ASSERT(s != NULL);

        TEST_ASSERT(!clawd_path_scanner_check(s, NULL));

        clawd_path_scanner_free(s);
    } TEST_END();

    TEST_BEGIN("null scanner is denied") {
        TEST_ASSERT(!clawd_path_scanner_check(NULL, "/some/path"));
    } TEST_END();
}

/* ---- audit tests -------------------------------------------------------- */

/* Sink callback that records the last event for verification. */
static clawd_audit_event_t last_sink_event;
static int sink_call_count = 0;

static void test_sink(const clawd_audit_event_t *event, void *userdata)
{
    (void)userdata;
    if (event) {
        last_sink_event = *event;
        sink_call_count++;
    }
}

static void test_audit(void)
{
    fprintf(stderr, "\n=== Audit Event Formatting ===\n");

    TEST_BEGIN("init and shutdown") {
        /* Use a temporary file. */
        char path[] = "/tmp/clawd_test_audit_XXXXXX";
        int fd = mkstemp(path);
        TEST_ASSERT(fd >= 0);
        close(fd);

        int rc = clawd_audit_init(path);
        TEST_ASSERT(rc == 0);

        clawd_audit_shutdown();
        unlink(path);
    } TEST_END();

    TEST_BEGIN("log event writes JSON line") {
        char path[] = "/tmp/clawd_test_audit_XXXXXX";
        int fd = mkstemp(path);
        TEST_ASSERT(fd >= 0);
        close(fd);

        int rc = clawd_audit_init(path);
        TEST_ASSERT(rc == 0);

        clawd_audit_event_t ev = {
            .level    = CLAWD_AUDIT_INFO,
            .timestamp = 1700000000,
            .category = "fs",
            .action   = "read",
            .subject  = "agent-1",
            .object   = "/home/user/test.txt",
            .detail   = "file access",
            .allowed  = true,
        };
        clawd_audit_log(&ev);
        clawd_audit_shutdown();

        /* Read back the log file and verify it contains expected fields. */
        FILE *fp = fopen(path, "r");
        TEST_ASSERT(fp != NULL);

        char line[4096] = {0};
        char *got = fgets(line, sizeof(line), fp);
        fclose(fp);
        unlink(path);

        TEST_ASSERT(got != NULL);
        TEST_ASSERT(strstr(line, "\"level\":\"info\"") != NULL);
        TEST_ASSERT(strstr(line, "\"category\":\"fs\"") != NULL);
        TEST_ASSERT(strstr(line, "\"action\":\"read\"") != NULL);
        TEST_ASSERT(strstr(line, "\"subject\":\"agent-1\"") != NULL);
        TEST_ASSERT(strstr(line, "\"object\":\"/home/user/test.txt\"") != NULL);
        TEST_ASSERT(strstr(line, "\"allowed\":true") != NULL);
    } TEST_END();

    TEST_BEGIN("min level filtering") {
        char path[] = "/tmp/clawd_test_audit_XXXXXX";
        int fd = mkstemp(path);
        TEST_ASSERT(fd >= 0);
        close(fd);

        int rc = clawd_audit_init(path);
        TEST_ASSERT(rc == 0);

        clawd_audit_set_min_level(CLAWD_AUDIT_ALERT);

        /* This event should be filtered out (INFO < ALERT). */
        clawd_audit_event_t ev_info = {
            .level    = CLAWD_AUDIT_INFO,
            .timestamp = 1700000000,
            .category = "test",
            .action   = "noop",
            .subject  = "test",
            .object   = "test",
            .allowed  = true,
        };
        clawd_audit_log(&ev_info);

        /* This event should pass (ALERT >= ALERT). */
        clawd_audit_event_t ev_alert = {
            .level    = CLAWD_AUDIT_ALERT,
            .timestamp = 1700000000,
            .category = "test",
            .action   = "alert",
            .subject  = "test",
            .object   = "test",
            .allowed  = false,
        };
        clawd_audit_log(&ev_alert);

        clawd_audit_shutdown();

        /* Verify only one line was written. */
        FILE *fp = fopen(path, "r");
        TEST_ASSERT(fp != NULL);

        int line_count = 0;
        char line[4096];
        while (fgets(line, sizeof(line), fp))
            line_count++;

        fclose(fp);
        unlink(path);

        TEST_ASSERT(line_count == 1);
    } TEST_END();

    TEST_BEGIN("sink callback receives events") {
        char path[] = "/tmp/clawd_test_audit_XXXXXX";
        int fd = mkstemp(path);
        TEST_ASSERT(fd >= 0);
        close(fd);

        int rc = clawd_audit_init(path);
        TEST_ASSERT(rc == 0);

        sink_call_count = 0;
        memset(&last_sink_event, 0, sizeof(last_sink_event));

        rc = clawd_audit_add_sink(test_sink, NULL);
        TEST_ASSERT(rc == 0);

        clawd_audit_event_t ev = {
            .level    = CLAWD_AUDIT_WARN,
            .timestamp = 1700000000,
            .category = "tool",
            .action   = "exec",
            .subject  = "user-42",
            .object   = "bash",
            .detail   = "command execution",
            .allowed  = true,
        };
        clawd_audit_log(&ev);

        TEST_ASSERT(sink_call_count == 1);
        TEST_ASSERT(last_sink_event.level == CLAWD_AUDIT_WARN);
        TEST_ASSERT(strcmp(last_sink_event.category, "tool") == 0);

        clawd_audit_shutdown();
        unlink(path);
    } TEST_END();

    TEST_BEGIN("violation level event") {
        char path[] = "/tmp/clawd_test_audit_XXXXXX";
        int fd = mkstemp(path);
        TEST_ASSERT(fd >= 0);
        close(fd);

        int rc = clawd_audit_init(path);
        TEST_ASSERT(rc == 0);

        clawd_audit_event_t ev = {
            .level    = CLAWD_AUDIT_VIOLATION,
            .timestamp = 1700000000,
            .category = "auth",
            .action   = "denied",
            .subject  = "attacker",
            .object   = "/etc/shadow",
            .detail   = "unauthorised access attempt",
            .allowed  = false,
        };
        clawd_audit_log(&ev);
        clawd_audit_shutdown();

        FILE *fp = fopen(path, "r");
        TEST_ASSERT(fp != NULL);

        char line[4096] = {0};
        char *got = fgets(line, sizeof(line), fp);
        fclose(fp);
        unlink(path);

        TEST_ASSERT(got != NULL);
        TEST_ASSERT(strstr(line, "\"level\":\"violation\"") != NULL);
        TEST_ASSERT(strstr(line, "\"allowed\":false") != NULL);
    } TEST_END();

    TEST_BEGIN("JSON escaping in event fields") {
        char path[] = "/tmp/clawd_test_audit_XXXXXX";
        int fd = mkstemp(path);
        TEST_ASSERT(fd >= 0);
        close(fd);

        int rc = clawd_audit_init(path);
        TEST_ASSERT(rc == 0);

        clawd_audit_event_t ev = {
            .level    = CLAWD_AUDIT_INFO,
            .timestamp = 1700000000,
            .category = "test",
            .action   = "test",
            .subject  = "user\"with\"quotes",
            .object   = "path\\with\\backslashes",
            .detail   = "line1\nline2\ttab",
            .allowed  = true,
        };
        clawd_audit_log(&ev);
        clawd_audit_shutdown();

        FILE *fp = fopen(path, "r");
        TEST_ASSERT(fp != NULL);

        char line[4096] = {0};
        char *got = fgets(line, sizeof(line), fp);
        fclose(fp);
        unlink(path);

        TEST_ASSERT(got != NULL);
        /* Verify that quotes and backslashes are escaped. */
        TEST_ASSERT(strstr(line, "\\\"") != NULL);
        TEST_ASSERT(strstr(line, "\\\\") != NULL);
        TEST_ASSERT(strstr(line, "\\n") != NULL);
        TEST_ASSERT(strstr(line, "\\t") != NULL);
    } TEST_END();
}

/* ---- scan permissions test ---------------------------------------------- */

static void test_scan_permissions(void)
{
    fprintf(stderr, "\n=== Permission Scanning ===\n");

    TEST_BEGIN("scan /tmp with depth 0") {
        /* Just ensure it does not crash. */
        int result = clawd_fs_scan_permissions("/tmp", 0);
        /* result >= 0 means it ran; -1 would be an error. */
        TEST_ASSERT(result >= 0);
    } TEST_END();

    TEST_BEGIN("scan nonexistent directory") {
        int result = clawd_fs_scan_permissions(
            "/nonexistent_dir_xyzzy_12345", 0);
        TEST_ASSERT(result == -1);
    } TEST_END();

    TEST_BEGIN("scan null directory") {
        int result = clawd_fs_scan_permissions(NULL, 0);
        TEST_ASSERT(result == -1);
    } TEST_END();
}


/* ---- timing-safe comparison tests --------------------------------------- */

static void test_timing_safe_cmp(void)
{
    fprintf(stderr, "\n=== Timing-Safe Comparison ===\n");

    TEST_BEGIN("equal strings return true") {
        const char *a = "supersecrettoken";
        const char *b = "supersecrettoken";
        TEST_ASSERT(clawd_timing_safe_cmp(a, b, 16));
    } TEST_END();

    TEST_BEGIN("equal binary data returns true") {
        unsigned char a[] = {0x00, 0xff, 0x42, 0xde, 0xad, 0xbe, 0xef, 0x01};
        unsigned char b[] = {0x00, 0xff, 0x42, 0xde, 0xad, 0xbe, 0xef, 0x01};
        TEST_ASSERT(clawd_timing_safe_cmp(a, b, sizeof(a)));
    } TEST_END();

    TEST_BEGIN("different strings return false") {
        const char *a = "supersecrettoken";
        const char *b = "differentsecrett";
        TEST_ASSERT(!clawd_timing_safe_cmp(a, b, 16));
    } TEST_END();

    TEST_BEGIN("single byte difference returns false") {
        const char *a = "abcdefgh";
        const char *b = "abcdefgi";
        TEST_ASSERT(!clawd_timing_safe_cmp(a, b, 8));
    } TEST_END();

    TEST_BEGIN("difference at first byte returns false") {
        const char *a = "Xbcdefgh";
        const char *b = "abcdefgh";
        TEST_ASSERT(!clawd_timing_safe_cmp(a, b, 8));
    } TEST_END();

    TEST_BEGIN("zero-length comparison returns true") {
        const char *a = "hello";
        const char *b = "world";
        TEST_ASSERT(clawd_timing_safe_cmp(a, b, 0));
    } TEST_END();

    TEST_BEGIN("both NULL with zero length returns true") {
        TEST_ASSERT(clawd_timing_safe_cmp(NULL, NULL, 0));
    } TEST_END();

    TEST_BEGIN("NULL first pointer returns false") {
        const char *b = "hello";
        TEST_ASSERT(!clawd_timing_safe_cmp(NULL, b, 5));
    } TEST_END();

    TEST_BEGIN("NULL second pointer returns false") {
        const char *a = "hello";
        TEST_ASSERT(!clawd_timing_safe_cmp(a, NULL, 5));
    } TEST_END();

    TEST_BEGIN("NULL pointer with zero length returns false") {
        const char *a = "hello";
        TEST_ASSERT(!clawd_timing_safe_cmp(NULL, a, 0));
        TEST_ASSERT(!clawd_timing_safe_cmp(a, NULL, 0));
    } TEST_END();

    TEST_BEGIN("both NULL with non-zero length returns false") {
        TEST_ASSERT(!clawd_timing_safe_cmp(NULL, NULL, 10));
    } TEST_END();

    TEST_BEGIN("single byte equal") {
        unsigned char a = 0x42;
        unsigned char b = 0x42;
        TEST_ASSERT(clawd_timing_safe_cmp(&a, &b, 1));
    } TEST_END();

    TEST_BEGIN("single byte different") {
        unsigned char a = 0x42;
        unsigned char b = 0x43;
        TEST_ASSERT(!clawd_timing_safe_cmp(&a, &b, 1));
    } TEST_END();
}

/* ---- main --------------------------------------------------------------- */

int main(void)
{
    fprintf(stderr, "libclawd-security test suite\n");
    fprintf(stderr, "============================\n");

    test_path_traversal();
    test_safe_resolution();
    test_fs_permissions();
    test_policy();
    test_path_scanner();
    test_audit();
    test_scan_permissions();
    test_timing_safe_cmp();

    fprintf(stderr, "\n============================\n");
    fprintf(stderr, "Results: %d/%d passed", pass_count, test_count);
    if (fail_count > 0)
        fprintf(stderr, ", %d FAILED", fail_count);
    fprintf(stderr, "\n");

    return fail_count > 0 ? 1 : 0;
}
