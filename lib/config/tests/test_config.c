/*
 * clawd-linux :: libclawd-config
 * test_config.c - Unit tests for config, schema, and paths modules
 *
 * SPDX-License-Identifier: MIT
 */

#include "clawd/config.h"
#include "clawd/paths.h"
#include "clawd/schema.h"

#include <cjson/cJSON.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ======================================================================== */
/* Test helpers                                                             */
/* ======================================================================== */

static int tests_run    = 0;
static int tests_passed = 0;

#define RUN_TEST(fn)                                           \
    do {                                                       \
        printf("  %-50s ", #fn);                               \
        fflush(stdout);                                        \
        tests_run++;                                           \
        fn();                                                  \
        tests_passed++;                                        \
        printf("[PASS]\n");                                    \
    } while (0)

#define ASSERT_TRUE(expr)                                      \
    do {                                                       \
        if (!(expr)) {                                         \
            fprintf(stderr, "\n    FAIL: %s:%d: %s\n",        \
                    __FILE__, __LINE__, #expr);                \
            abort();                                           \
        }                                                      \
    } while (0)

#define ASSERT_EQ_INT(a, b)                                    \
    do {                                                       \
        int _a = (a), _b = (b);                                \
        if (_a != _b) {                                        \
            fprintf(stderr, "\n    FAIL: %s:%d: %d != %d\n",  \
                    __FILE__, __LINE__, _a, _b);               \
            abort();                                           \
        }                                                      \
    } while (0)

#define ASSERT_EQ_STR(a, b)                                    \
    do {                                                       \
        const char *_a = (a), *_b = (b);                       \
        if (!_a || !_b || strcmp(_a, _b) != 0) {               \
            fprintf(stderr, "\n    FAIL: %s:%d: \"%s\" != \"%s\"\n", \
                    __FILE__, __LINE__,                        \
                    _a ? _a : "(null)", _b ? _b : "(null)");   \
            abort();                                           \
        }                                                      \
    } while (0)

#define ASSERT_NOT_NULL(p)                                     \
    do {                                                       \
        if ((p) == NULL) {                                     \
            fprintf(stderr, "\n    FAIL: %s:%d: NULL\n",      \
                    __FILE__, __LINE__);                       \
            abort();                                           \
        }                                                      \
    } while (0)

/* ======================================================================== */
/* Write a temp YAML config file                                             */
/* ======================================================================== */

static const char *sample_yaml =
    "profile: testing\n"
    "\n"
    "gateway:\n"
    "  host: 0.0.0.0\n"
    "  port: 9090\n"
    "  socket_path: /tmp/clawd-test.sock\n"
    "  tls_enabled: false\n"
    "\n"
    "model:\n"
    "  default_provider: anthropic\n"
    "  default_model: claude-sonnet-4-20250514\n"
    "  api_key: ${TEST_API_KEY:-sk-test-placeholder}\n"
    "  max_tokens: 8192\n"
    "  temperature: 0.5\n"
    "\n"
    "security:\n"
    "  sandbox_enabled: true\n"
    "  sandbox_memory_mb: 1024\n"
    "  sandbox_cpu_cores: 4\n"
    "  sandbox_max_pids: 128\n"
    "  allowed_paths:\n"
    "    - /home\n"
    "    - /tmp\n"
    "\n"
    "logging:\n"
    "  level: debug\n"
    "  file: /var/log/clawd/test.log\n";

static char tmp_yaml_path[512] = {0};

static void
write_temp_yaml(void)
{
    snprintf(tmp_yaml_path, sizeof(tmp_yaml_path),
             "/tmp/clawd_test_%d.yaml", (int)getpid());
    FILE *fp = fopen(tmp_yaml_path, "w");
    assert(fp);
    fputs(sample_yaml, fp);
    fclose(fp);
}

static void
cleanup_temp(void)
{
    if (tmp_yaml_path[0])
        unlink(tmp_yaml_path);
}

/* ======================================================================== */
/* Tests: config loading                                                     */
/* ======================================================================== */

static void
test_load_yaml(void)
{
    clawd_config_t cfg;
    int rc = clawd_config_load(tmp_yaml_path, &cfg);
    ASSERT_EQ_INT(rc, 0);

    ASSERT_EQ_STR(cfg.profile, "testing");
    ASSERT_EQ_STR(cfg.gateway.host, "0.0.0.0");
    ASSERT_EQ_INT(cfg.gateway.port, 9090);
    ASSERT_EQ_STR(cfg.gateway.socket_path, "/tmp/clawd-test.sock");
    ASSERT_TRUE(!cfg.gateway.tls_enabled);

    ASSERT_EQ_STR(cfg.model.default_provider, "anthropic");
    ASSERT_EQ_STR(cfg.model.default_model, "claude-sonnet-4-20250514");
    ASSERT_EQ_INT(cfg.model.max_tokens, 8192);
    ASSERT_TRUE(cfg.model.temperature > 0.49f && cfg.model.temperature < 0.51f);

    ASSERT_TRUE(cfg.security.sandbox_enabled);
    ASSERT_EQ_INT(cfg.security.sandbox_memory_mb, 1024);
    ASSERT_EQ_INT(cfg.security.sandbox_cpu_cores, 4);
    ASSERT_EQ_INT(cfg.security.sandbox_max_pids, 128);
    ASSERT_EQ_INT(cfg.security.allowed_paths_count, 2);
    ASSERT_EQ_STR(cfg.security.allowed_paths[0], "/home");
    ASSERT_EQ_STR(cfg.security.allowed_paths[1], "/tmp");

    ASSERT_EQ_INT(cfg.logging.level, CLAWD_LOG_DEBUG);
    ASSERT_EQ_STR(cfg.logging.file, "/var/log/clawd/test.log");

    clawd_config_free(&cfg);
}

static void
test_load_nonexistent(void)
{
    clawd_config_t cfg;
    int rc = clawd_config_load("/no/such/file.yaml", &cfg);
    ASSERT_EQ_INT(rc, -1);
}

static void
test_load_default_fills_defaults(void)
{
    /* Make sure CLAWD_CONFIG_DIR doesn't point at a real file for this test */
    unsetenv("CLAWD_CONFIG_DIR");

    clawd_config_t cfg;
    int rc = clawd_config_load_default(&cfg);
    ASSERT_EQ_INT(rc, 0);

    /* Should have sensible defaults */
    ASSERT_NOT_NULL(cfg.gateway.host);
    ASSERT_EQ_STR(cfg.gateway.host, "127.0.0.1");
    ASSERT_EQ_INT(cfg.gateway.port, 8080);
    ASSERT_EQ_STR(cfg.model.default_provider, "anthropic");
    ASSERT_EQ_INT(cfg.model.max_tokens, 4096);
    ASSERT_TRUE(cfg.security.sandbox_enabled);
    ASSERT_EQ_INT(cfg.logging.level, CLAWD_LOG_INFO);

    clawd_config_free(&cfg);
}

/* ======================================================================== */
/* Tests: env substitution                                                   */
/* ======================================================================== */

static void
test_env_subst_default_value(void)
{
    /* TEST_API_KEY is not set, so the default should be used */
    unsetenv("TEST_API_KEY");

    clawd_config_t cfg;
    int rc = clawd_config_load(tmp_yaml_path, &cfg);
    ASSERT_EQ_INT(rc, 0);

    ASSERT_EQ_STR(cfg.model.api_key, "sk-test-placeholder");

    clawd_config_free(&cfg);
}

static void
test_env_subst_real_value(void)
{
    setenv("TEST_API_KEY", "sk-real-key-123", 1);

    clawd_config_t cfg;
    int rc = clawd_config_load(tmp_yaml_path, &cfg);
    ASSERT_EQ_INT(rc, 0);

    ASSERT_EQ_STR(cfg.model.api_key, "sk-real-key-123");

    clawd_config_free(&cfg);
    unsetenv("TEST_API_KEY");
}

static void
test_merge_env(void)
{
    clawd_config_t cfg;
    int rc = clawd_config_load(tmp_yaml_path, &cfg);
    ASSERT_EQ_INT(rc, 0);

    /* Override via env */
    setenv("CLAWD_HOST", "10.0.0.1", 1);
    setenv("CLAWD_PORT", "3000", 1);
    setenv("CLAWD_PROVIDER", "openai", 1);
    setenv("CLAWD_LOG_LEVEL", "warn", 1);
    setenv("CLAWD_SANDBOX", "no", 1);

    clawd_config_merge_env(&cfg);

    ASSERT_EQ_STR(cfg.gateway.host, "10.0.0.1");
    ASSERT_EQ_INT(cfg.gateway.port, 3000);
    ASSERT_EQ_STR(cfg.model.default_provider, "openai");
    ASSERT_EQ_INT(cfg.logging.level, CLAWD_LOG_WARNING);
    ASSERT_TRUE(!cfg.security.sandbox_enabled);

    clawd_config_free(&cfg);

    unsetenv("CLAWD_HOST");
    unsetenv("CLAWD_PORT");
    unsetenv("CLAWD_PROVIDER");
    unsetenv("CLAWD_LOG_LEVEL");
    unsetenv("CLAWD_SANDBOX");
}

/* ======================================================================== */
/* Tests: keyed accessors                                                    */
/* ======================================================================== */

static void
test_get_string(void)
{
    clawd_config_t cfg;
    int rc = clawd_config_load(tmp_yaml_path, &cfg);
    ASSERT_EQ_INT(rc, 0);

    ASSERT_EQ_STR(clawd_config_get_string(&cfg, "gateway.host"), "0.0.0.0");
    ASSERT_EQ_STR(clawd_config_get_string(&cfg, "model.default_provider"), "anthropic");
    ASSERT_TRUE(clawd_config_get_string(&cfg, "nonexistent.key") == NULL);

    clawd_config_free(&cfg);
}

static void
test_get_int(void)
{
    clawd_config_t cfg;
    int rc = clawd_config_load(tmp_yaml_path, &cfg);
    ASSERT_EQ_INT(rc, 0);

    ASSERT_EQ_INT(clawd_config_get_int(&cfg, "gateway.port", -1), 9090);
    ASSERT_EQ_INT(clawd_config_get_int(&cfg, "model.max_tokens", -1), 8192);
    ASSERT_EQ_INT(clawd_config_get_int(&cfg, "nonexistent", 42), 42);

    clawd_config_free(&cfg);
}

static void
test_get_bool(void)
{
    clawd_config_t cfg;
    int rc = clawd_config_load(tmp_yaml_path, &cfg);
    ASSERT_EQ_INT(rc, 0);

    ASSERT_TRUE(clawd_config_get_bool(&cfg, "security.sandbox_enabled", false));
    ASSERT_TRUE(!clawd_config_get_bool(&cfg, "gateway.tls_enabled", true));
    ASSERT_TRUE(clawd_config_get_bool(&cfg, "nonexistent", true));

    clawd_config_free(&cfg);
}

/* ======================================================================== */
/* Tests: validation                                                         */
/* ======================================================================== */

static void
test_validate_good(void)
{
    clawd_config_t cfg;
    int rc = clawd_config_load(tmp_yaml_path, &cfg);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_EQ_INT(clawd_config_validate(&cfg), 0);
    clawd_config_free(&cfg);
}

static void
test_validate_bad_port(void)
{
    clawd_config_t cfg;
    int rc = clawd_config_load(tmp_yaml_path, &cfg);
    ASSERT_EQ_INT(rc, 0);

    cfg.gateway.port = 99999;
    ASSERT_EQ_INT(clawd_config_validate(&cfg), -1);

    clawd_config_free(&cfg);
}

static void
test_validate_bad_temperature(void)
{
    clawd_config_t cfg;
    int rc = clawd_config_load(tmp_yaml_path, &cfg);
    ASSERT_EQ_INT(rc, 0);

    cfg.model.temperature = 5.0f;
    ASSERT_EQ_INT(clawd_config_validate(&cfg), -1);

    clawd_config_free(&cfg);
}

static void
test_validate_tls_missing_cert(void)
{
    clawd_config_t cfg;
    int rc = clawd_config_load(tmp_yaml_path, &cfg);
    ASSERT_EQ_INT(rc, 0);

    cfg.gateway.tls_enabled = true;
    /* cert and key are NULL -> should fail */
    free(cfg.gateway.tls_cert);
    cfg.gateway.tls_cert = NULL;
    free(cfg.gateway.tls_key);
    cfg.gateway.tls_key = NULL;
    ASSERT_EQ_INT(clawd_config_validate(&cfg), -1);

    clawd_config_free(&cfg);
}

/* ======================================================================== */
/* Tests: schema validation                                                  */
/* ======================================================================== */

static void
test_schema_validate_good(void)
{
    const char *json_str =
        "{"
        "  \"gateway\": {"
        "    \"host\": \"127.0.0.1\","
        "    \"port\": 8080"
        "  },"
        "  \"model\": {"
        "    \"default_provider\": \"anthropic\","
        "    \"max_tokens\": 4096,"
        "    \"temperature\": 0.7"
        "  },"
        "  \"security\": {"
        "    \"sandbox_enabled\": true,"
        "    \"sandbox_memory_mb\": 512,"
        "    \"sandbox_cpu_cores\": 2,"
        "    \"sandbox_max_pids\": 64"
        "  },"
        "  \"logging\": {"
        "    \"level\": 6"
        "  }"
        "}";

    cJSON *root = cJSON_Parse(json_str);
    ASSERT_NOT_NULL(root);

    const clawd_schema_t *schema = clawd_schema_config();
    char err[256] = {0};
    int rc = clawd_schema_validate(schema, root, err, sizeof(err));
    ASSERT_EQ_INT(rc, 0);

    cJSON_Delete(root);
}

static void
test_schema_validate_bad_type(void)
{
    const char *json_str =
        "{"
        "  \"gateway\": {"
        "    \"host\": 12345"  /* should be string */
        "  }"
        "}";

    cJSON *root = cJSON_Parse(json_str);
    ASSERT_NOT_NULL(root);

    const clawd_schema_t *schema = clawd_schema_config();
    char err[256] = {0};
    int rc = clawd_schema_validate(schema, root, err, sizeof(err));
    ASSERT_EQ_INT(rc, -1);
    ASSERT_TRUE(strlen(err) > 0);

    cJSON_Delete(root);
}

static void
test_schema_validate_bad_range(void)
{
    const char *json_str =
        "{"
        "  \"gateway\": {"
        "    \"port\": 99999"  /* exceeds max 65535 */
        "  }"
        "}";

    cJSON *root = cJSON_Parse(json_str);
    ASSERT_NOT_NULL(root);

    const clawd_schema_t *schema = clawd_schema_config();
    char err[256] = {0};
    int rc = clawd_schema_validate(schema, root, err, sizeof(err));
    ASSERT_EQ_INT(rc, -1);
    ASSERT_TRUE(strstr(err, "max") != NULL || strstr(err, "port") != NULL);

    cJSON_Delete(root);
}

/* ======================================================================== */
/* Tests: path resolution                                                    */
/* ======================================================================== */

static void
test_paths_config_dir(void)
{
    unsetenv("CLAWD_CONFIG_DIR");
    unsetenv("XDG_CONFIG_HOME");

    char *dir = clawd_paths_config_dir();
    ASSERT_NOT_NULL(dir);
    /* Should end with ".config/clawd" */
    ASSERT_TRUE(strlen(dir) > 13);
    const char *tail = dir + strlen(dir) - 13;
    ASSERT_EQ_STR(tail, ".config/clawd");

    free(dir);
}

static void
test_paths_config_dir_env(void)
{
    setenv("CLAWD_CONFIG_DIR", "/opt/clawd/conf", 1);

    char *dir = clawd_paths_config_dir();
    ASSERT_NOT_NULL(dir);
    ASSERT_EQ_STR(dir, "/opt/clawd/conf");

    free(dir);
    unsetenv("CLAWD_CONFIG_DIR");
}

static void
test_paths_expand_tilde(void)
{
    const char *home = getenv("HOME");
    if (!home)
        return; /* skip if HOME not set */

    char *result = clawd_paths_expand("~/foo/bar");
    ASSERT_NOT_NULL(result);

    /* Should start with HOME */
    ASSERT_TRUE(strncmp(result, home, strlen(home)) == 0);
    /* Should end with /foo/bar */
    ASSERT_TRUE(strstr(result, "/foo/bar") != NULL);

    free(result);
}

static void
test_paths_expand_env_var(void)
{
    setenv("CLAWD_TEST_VAR", "hello", 1);

    char *result = clawd_paths_expand("/prefix/${CLAWD_TEST_VAR}/suffix");
    ASSERT_NOT_NULL(result);
    ASSERT_EQ_STR(result, "/prefix/hello/suffix");

    free(result);
    unsetenv("CLAWD_TEST_VAR");
}

static void
test_paths_expand_default(void)
{
    unsetenv("CLAWD_UNSET_VAR");

    char *result = clawd_paths_expand("/path/${CLAWD_UNSET_VAR:-fallback}/end");
    ASSERT_NOT_NULL(result);
    ASSERT_EQ_STR(result, "/path/fallback/end");

    free(result);
}

static void
test_paths_socket(void)
{
    char *sock = clawd_paths_socket();
    ASSERT_NOT_NULL(sock);
    ASSERT_TRUE(strstr(sock, "clawd.sock") != NULL);
    free(sock);
}

/* ======================================================================== */
/* Tests: JSON config loading                                                */
/* ======================================================================== */

static char tmp_json_path[512] = {0};

static void
write_temp_json(void)
{
    snprintf(tmp_json_path, sizeof(tmp_json_path),
             "/tmp/clawd_test_%d.json", (int)getpid());

    const char *json =
        "{\n"
        "  \"profile\": \"json-test\",\n"
        "  \"gateway\": {\n"
        "    \"host\": \"192.168.1.1\",\n"
        "    \"port\": 7070\n"
        "  },\n"
        "  \"model\": {\n"
        "    \"default_provider\": \"openai\",\n"
        "    \"max_tokens\": 2048,\n"
        "    \"temperature\": 0.3\n"
        "  },\n"
        "  \"security\": {\n"
        "    \"sandbox_enabled\": false,\n"
        "    \"sandbox_memory_mb\": 256,\n"
        "    \"sandbox_cpu_cores\": 1,\n"
        "    \"sandbox_max_pids\": 32\n"
        "  },\n"
        "  \"logging\": {\n"
        "    \"level\": 3\n"
        "  }\n"
        "}\n";

    FILE *fp = fopen(tmp_json_path, "w");
    assert(fp);
    fputs(json, fp);
    fclose(fp);
}

static void
cleanup_json(void)
{
    if (tmp_json_path[0])
        unlink(tmp_json_path);
}

static void
test_load_json(void)
{
    write_temp_json();

    clawd_config_t cfg;
    int rc = clawd_config_load(tmp_json_path, &cfg);
    ASSERT_EQ_INT(rc, 0);

    ASSERT_EQ_STR(cfg.profile, "json-test");
    ASSERT_EQ_STR(cfg.gateway.host, "192.168.1.1");
    ASSERT_EQ_INT(cfg.gateway.port, 7070);
    ASSERT_EQ_STR(cfg.model.default_provider, "openai");
    ASSERT_EQ_INT(cfg.model.max_tokens, 2048);
    ASSERT_TRUE(!cfg.security.sandbox_enabled);
    ASSERT_EQ_INT(cfg.security.sandbox_memory_mb, 256);
    ASSERT_EQ_INT(cfg.logging.level, CLAWD_LOG_ERR);

    clawd_config_free(&cfg);
    cleanup_json();
}

/* ======================================================================== */
/* Tests: config_free idempotence                                            */
/* ======================================================================== */

static void
test_free_zeroed(void)
{
    /* Freeing a zeroed struct should not crash */
    clawd_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    clawd_config_free(&cfg);
    /* If we get here, it passed */
}

static void
test_free_null(void)
{
    /* Passing NULL should not crash */
    clawd_config_free(NULL);
}

/* ======================================================================== */
/* Main                                                                      */
/* ======================================================================== */

int
main(void)
{
    printf("libclawd-config test suite\n");
    printf("==========================\n\n");

    /* Set up temp files */
    write_temp_yaml();

    /* Config loading */
    printf("Config loading:\n");
    RUN_TEST(test_load_yaml);
    RUN_TEST(test_load_json);
    RUN_TEST(test_load_nonexistent);
    RUN_TEST(test_load_default_fills_defaults);

    /* Env substitution */
    printf("\nEnvironment substitution:\n");
    RUN_TEST(test_env_subst_default_value);
    RUN_TEST(test_env_subst_real_value);
    RUN_TEST(test_merge_env);

    /* Keyed accessors */
    printf("\nKeyed accessors:\n");
    RUN_TEST(test_get_string);
    RUN_TEST(test_get_int);
    RUN_TEST(test_get_bool);

    /* Validation */
    printf("\nValidation:\n");
    RUN_TEST(test_validate_good);
    RUN_TEST(test_validate_bad_port);
    RUN_TEST(test_validate_bad_temperature);
    RUN_TEST(test_validate_tls_missing_cert);

    /* Schema validation */
    printf("\nSchema validation:\n");
    RUN_TEST(test_schema_validate_good);
    RUN_TEST(test_schema_validate_bad_type);
    RUN_TEST(test_schema_validate_bad_range);

    /* Path resolution */
    printf("\nPath resolution:\n");
    RUN_TEST(test_paths_config_dir);
    RUN_TEST(test_paths_config_dir_env);
    RUN_TEST(test_paths_expand_tilde);
    RUN_TEST(test_paths_expand_env_var);
    RUN_TEST(test_paths_expand_default);
    RUN_TEST(test_paths_socket);

    /* Memory safety */
    printf("\nMemory safety:\n");
    RUN_TEST(test_free_zeroed);
    RUN_TEST(test_free_null);

    /* Cleanup */
    cleanup_temp();

    printf("\n==========================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
