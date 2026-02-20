/*
 * clawd-linux :: libclawd-agents
 * test_agents.c - Unit tests for provider, tool, and agent APIs
 *
 * Tests message creation/linking, tool registration, tool definitions
 * JSON generation, and provider creation (without actual API calls).
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <clawd/provider.h>
#include <clawd/tool.h>
#include <clawd/agent.h>
#include <clawd/sandbox.h>

/* ---- Message tests ------------------------------------------------------ */

static void test_message_new(void)
{
    clawd_message_t *msg = clawd_message_new(CLAWD_ROLE_USER, "hello");
    assert(msg != NULL);
    assert(msg->role == CLAWD_ROLE_USER);
    assert(strcmp(msg->content, "hello") == 0);
    assert(msg->next == NULL);
    assert(msg->tool_call_id == NULL);
    assert(msg->tool_name == NULL);
    assert(msg->tool_args == NULL);
    clawd_message_free(msg);
    printf("  PASS: message_new\n");
}

static void test_message_new_null_content(void)
{
    clawd_message_t *msg = clawd_message_new(CLAWD_ROLE_ASSISTANT, NULL);
    assert(msg != NULL);
    assert(msg->role == CLAWD_ROLE_ASSISTANT);
    assert(msg->content == NULL);
    clawd_message_free(msg);
    printf("  PASS: message_new with NULL content\n");
}

static void test_message_append(void)
{
    clawd_message_t *list = NULL;

    clawd_message_t *m1 = clawd_message_new(CLAWD_ROLE_USER, "first");
    clawd_message_t *m2 = clawd_message_new(CLAWD_ROLE_ASSISTANT, "second");
    clawd_message_t *m3 = clawd_message_new(CLAWD_ROLE_USER, "third");

    clawd_message_append(&list, m1);
    assert(list == m1);
    assert(list->next == NULL);

    clawd_message_append(&list, m2);
    assert(list == m1);
    assert(list->next == m2);
    assert(m2->next == NULL);

    clawd_message_append(&list, m3);
    assert(list->next->next == m3);
    assert(m3->next == NULL);

    /* Verify traversal */
    int count = 0;
    for (clawd_message_t *m = list; m; m = m->next) count++;
    assert(count == 3);

    clawd_message_free(list);
    printf("  PASS: message_append linked list\n");
}

static void test_message_free_null(void)
{
    /* Should not crash */
    clawd_message_free(NULL);
    printf("  PASS: message_free NULL\n");
}

static void test_message_roles(void)
{
    clawd_message_t *m;

    m = clawd_message_new(CLAWD_ROLE_SYSTEM, "system prompt");
    assert(m->role == CLAWD_ROLE_SYSTEM);
    clawd_message_free(m);

    m = clawd_message_new(CLAWD_ROLE_TOOL, "tool result");
    assert(m->role == CLAWD_ROLE_TOOL);
    clawd_message_free(m);

    printf("  PASS: message roles\n");
}

static void test_message_tool_fields(void)
{
    clawd_message_t *msg = clawd_message_new(CLAWD_ROLE_ASSISTANT, NULL);
    assert(msg != NULL);

    msg->tool_call_id = strdup("call_123");
    msg->tool_name    = strdup("bash");
    msg->tool_args    = strdup("{\"command\":\"ls\"}");

    assert(strcmp(msg->tool_call_id, "call_123") == 0);
    assert(strcmp(msg->tool_name, "bash") == 0);
    assert(strcmp(msg->tool_args, "{\"command\":\"ls\"}") == 0);

    clawd_message_free(msg);
    printf("  PASS: message tool fields\n");
}

/* ---- Tool tests --------------------------------------------------------- */

static int dummy_tool_exec(clawd_tool_ctx_t *ctx, const char *args_json,
                           clawd_tool_result_t *result)
{
    (void)ctx;
    (void)args_json;
    result->output    = strdup("dummy output");
    result->is_error  = false;
    result->exit_code = 0;
    return 0;
}

static int error_tool_exec(clawd_tool_ctx_t *ctx, const char *args_json,
                           clawd_tool_result_t *result)
{
    (void)ctx;
    (void)args_json;
    result->output    = strdup("something went wrong");
    result->is_error  = true;
    result->exit_code = 1;
    return 0;
}

static void test_tool_ctx_create(void)
{
    clawd_tool_ctx_t *ctx = clawd_tool_ctx_new("/tmp/workspace");
    assert(ctx != NULL);
    clawd_tool_ctx_free(ctx);
    printf("  PASS: tool_ctx_new/free\n");
}

static void test_tool_ctx_null_workspace(void)
{
    clawd_tool_ctx_t *ctx = clawd_tool_ctx_new(NULL);
    assert(ctx != NULL);
    clawd_tool_ctx_free(ctx);
    printf("  PASS: tool_ctx_new with NULL workspace\n");
}

static void test_tool_register(void)
{
    clawd_tool_ctx_t *ctx = clawd_tool_ctx_new("/tmp");
    assert(ctx != NULL);

    clawd_tool_def_t def = {
        .name        = "test_tool",
        .description = "A test tool",
        .params_json = "{\"type\":\"object\",\"properties\":{}}",
        .exec        = dummy_tool_exec,
        .requires_sandbox     = false,
        .requires_confirmation = false
    };

    int rc = clawd_tool_register(ctx, &def);
    assert(rc == 0);

    clawd_tool_ctx_free(ctx);
    printf("  PASS: tool_register\n");
}

static void test_tool_register_multiple(void)
{
    clawd_tool_ctx_t *ctx = clawd_tool_ctx_new("/tmp");

    clawd_tool_def_t def1 = {
        .name = "tool_a", .description = "Tool A",
        .params_json = "{}", .exec = dummy_tool_exec
    };
    clawd_tool_def_t def2 = {
        .name = "tool_b", .description = "Tool B",
        .params_json = "{}", .exec = error_tool_exec
    };

    assert(clawd_tool_register(ctx, &def1) == 0);
    assert(clawd_tool_register(ctx, &def2) == 0);

    clawd_tool_ctx_free(ctx);
    printf("  PASS: tool_register multiple\n");
}

static void test_tool_execute(void)
{
    clawd_tool_ctx_t *ctx = clawd_tool_ctx_new("/tmp");

    clawd_tool_def_t def = {
        .name = "hello", .description = "Says hello",
        .params_json = "{}", .exec = dummy_tool_exec
    };
    clawd_tool_register(ctx, &def);

    clawd_tool_result_t result = {0};
    int rc = clawd_tool_execute(ctx, "hello", "{}", &result);
    assert(rc == 0);
    assert(result.output != NULL);
    assert(strcmp(result.output, "dummy output") == 0);
    assert(result.is_error == false);
    assert(result.exit_code == 0);

    clawd_tool_result_free(&result);
    clawd_tool_ctx_free(ctx);
    printf("  PASS: tool_execute\n");
}

static void test_tool_execute_error(void)
{
    clawd_tool_ctx_t *ctx = clawd_tool_ctx_new("/tmp");

    clawd_tool_def_t def = {
        .name = "fail", .description = "Fails",
        .params_json = "{}", .exec = error_tool_exec
    };
    clawd_tool_register(ctx, &def);

    clawd_tool_result_t result = {0};
    int rc = clawd_tool_execute(ctx, "fail", "{}", &result);
    assert(rc == 0);
    assert(result.is_error == true);
    assert(result.exit_code == 1);

    clawd_tool_result_free(&result);
    clawd_tool_ctx_free(ctx);
    printf("  PASS: tool_execute error tool\n");
}

static void test_tool_execute_not_found(void)
{
    clawd_tool_ctx_t *ctx = clawd_tool_ctx_new("/tmp");

    clawd_tool_result_t result = {0};
    int rc = clawd_tool_execute(ctx, "nonexistent", "{}", &result);
    assert(rc == -1);
    assert(result.is_error == true);
    assert(result.output != NULL);
    assert(strstr(result.output, "unknown tool") != NULL);

    clawd_tool_result_free(&result);
    clawd_tool_ctx_free(ctx);
    printf("  PASS: tool_execute not found\n");
}

static void test_tool_definitions_json(void)
{
    clawd_tool_ctx_t *ctx = clawd_tool_ctx_new("/tmp");

    clawd_tool_def_t def1 = {
        .name = "tool_alpha",
        .description = "First tool",
        .params_json = "{\"type\":\"object\",\"properties\":{\"x\":{\"type\":\"string\"}}}",
        .exec = dummy_tool_exec
    };
    clawd_tool_def_t def2 = {
        .name = "tool_beta",
        .description = "Second tool",
        .params_json = "{\"type\":\"object\",\"properties\":{}}",
        .exec = dummy_tool_exec
    };

    clawd_tool_register(ctx, &def1);
    clawd_tool_register(ctx, &def2);

    char *json = clawd_tool_get_definitions_json(ctx);
    assert(json != NULL);

    /* Should be a valid JSON array containing both tools */
    assert(json[0] == '[');
    assert(strstr(json, "tool_alpha") != NULL);
    assert(strstr(json, "tool_beta") != NULL);
    assert(strstr(json, "First tool") != NULL);
    assert(strstr(json, "Second tool") != NULL);
    assert(strstr(json, "input_schema") != NULL);

    free(json);
    clawd_tool_ctx_free(ctx);
    printf("  PASS: tool_definitions_json\n");
}

static void test_tool_definitions_empty(void)
{
    clawd_tool_ctx_t *ctx = clawd_tool_ctx_new("/tmp");

    char *json = clawd_tool_get_definitions_json(ctx);
    assert(json != NULL);
    assert(strcmp(json, "[]") == 0);

    free(json);
    clawd_tool_ctx_free(ctx);
    printf("  PASS: tool_definitions_json empty\n");
}

static void test_tool_result_free(void)
{
    clawd_tool_result_t result = {0};
    result.output = strdup("test");
    result.is_error = true;
    result.exit_code = 42;

    clawd_tool_result_free(&result);
    assert(result.output == NULL);
    assert(result.is_error == false);
    assert(result.exit_code == 0);

    /* Should not crash on NULL */
    clawd_tool_result_free(NULL);
    printf("  PASS: tool_result_free\n");
}

/* ---- Provider tests ----------------------------------------------------- */

static void test_provider_create_anthropic(void)
{
    clawd_provider_t *p = clawd_provider_new(CLAWD_PROVIDER_ANTHROPIC, "test-key");
    assert(p != NULL);
    assert(p->type == CLAWD_PROVIDER_ANTHROPIC);
    assert(p->api_key != NULL);
    assert(strcmp(p->api_key, "test-key") == 0);
    assert(p->complete != NULL);
    clawd_provider_free(p);
    printf("  PASS: provider_new anthropic\n");
}

static void test_provider_create_openai(void)
{
    clawd_provider_t *p = clawd_provider_new(CLAWD_PROVIDER_OPENAI, "sk-test");
    assert(p != NULL);
    assert(p->type == CLAWD_PROVIDER_OPENAI);
    assert(p->complete != NULL);
    clawd_provider_free(p);
    printf("  PASS: provider_new openai\n");
}

static void test_provider_create_ollama(void)
{
    clawd_provider_t *p = clawd_provider_new(CLAWD_PROVIDER_OLLAMA, NULL);
    assert(p != NULL);
    assert(p->type == CLAWD_PROVIDER_OLLAMA);
    assert(p->complete != NULL);
    clawd_provider_free(p);
    printf("  PASS: provider_new ollama\n");
}

static void test_provider_create_google(void)
{
    clawd_provider_t *p = clawd_provider_new(CLAWD_PROVIDER_GOOGLE, "google-key");
    assert(p != NULL);
    assert(p->type == CLAWD_PROVIDER_GOOGLE);
    assert(p->complete != NULL);
    clawd_provider_free(p);
    printf("  PASS: provider_new google\n");
}

static void test_provider_create_bedrock(void)
{
    clawd_provider_t *p = clawd_provider_new(CLAWD_PROVIDER_BEDROCK, NULL);
    assert(p != NULL);
    assert(p->type == CLAWD_PROVIDER_BEDROCK);
    assert(p->complete != NULL);
    assert(p->ctx != NULL);   /* bedrock creates its own context */
    clawd_provider_free(p);
    printf("  PASS: provider_new bedrock\n");
}

static void test_provider_free_null(void)
{
    clawd_provider_free(NULL);  /* should not crash */
    printf("  PASS: provider_free NULL\n");
}

static void test_completion_free(void)
{
    clawd_completion_t c = {0};
    c.content     = strdup("test response");
    c.stop_reason = strdup("end_turn");
    c.model       = strdup("claude-3");
    c.id          = strdup("msg_123");
    c.input_tokens  = 100;
    c.output_tokens = 50;

    clawd_completion_free(&c);
    assert(c.content == NULL);
    assert(c.stop_reason == NULL);
    assert(c.model == NULL);
    assert(c.id == NULL);
    assert(c.input_tokens == 0);
    assert(c.output_tokens == 0);

    /* Should handle NULL */
    clawd_completion_free(NULL);
    printf("  PASS: completion_free\n");
}

/* ---- Sandbox tests ------------------------------------------------------ */

static void test_sandbox_defaults(void)
{
    clawd_sandbox_opts_t opts;
    clawd_sandbox_default_opts(&opts);
    assert(opts.memory_limit_mb == 256);
    assert(opts.cpu_cores == 1);
    assert(opts.max_pids == 256);
    assert(opts.timeout_sec == 30);
    assert(opts.enable_network == false);
    printf("  PASS: sandbox_default_opts\n");
}

static void test_sandbox_create(void)
{
    clawd_sandbox_opts_t opts;
    clawd_sandbox_default_opts(&opts);
    opts.workspace = "/tmp";

    clawd_sandbox_t *sb = clawd_sandbox_new(&opts);
    assert(sb != NULL);
    clawd_sandbox_free(sb);
    printf("  PASS: sandbox_new/free\n");
}

static void test_sandbox_available(void)
{
    /* Just test that it doesn't crash */
    bool avail = clawd_sandbox_available();
    printf("  PASS: sandbox_available (result=%s)\n", avail ? "true" : "false");
}

/* ---- Agent tests -------------------------------------------------------- */

static void test_agent_create(void)
{
    clawd_provider_t *p = clawd_provider_new(CLAWD_PROVIDER_ANTHROPIC, "key");
    assert(p != NULL);

    clawd_tool_ctx_t *tools = clawd_tool_ctx_new("/tmp");
    assert(tools != NULL);

    clawd_agent_opts_t opts = {
        .provider      = p,
        .tools         = tools,
        .system_prompt = "You are a helpful assistant.",
        .max_turns     = 5
    };

    clawd_agent_t *a = clawd_agent_new(&opts);
    assert(a != NULL);

    /* History should be empty initially */
    clawd_message_t *hist = clawd_agent_get_history(a);
    assert(hist == NULL);

    clawd_agent_free(a);
    clawd_tool_ctx_free(tools);
    clawd_provider_free(p);
    printf("  PASS: agent_new/free\n");
}

static void test_agent_reset(void)
{
    clawd_provider_t *p = clawd_provider_new(CLAWD_PROVIDER_ANTHROPIC, "key");
    clawd_agent_opts_t opts = { .provider = p };
    clawd_agent_t *a = clawd_agent_new(&opts);
    assert(a != NULL);

    clawd_agent_reset(a);
    assert(clawd_agent_get_history(a) == NULL);

    clawd_agent_free(a);
    clawd_provider_free(p);
    printf("  PASS: agent_reset\n");
}

/* ---- Main --------------------------------------------------------------- */

int main(void)
{
    printf("=== libclawd-agents tests ===\n");

    printf("\n-- Messages --\n");
    test_message_new();
    test_message_new_null_content();
    test_message_append();
    test_message_free_null();
    test_message_roles();
    test_message_tool_fields();

    printf("\n-- Tools --\n");
    test_tool_ctx_create();
    test_tool_ctx_null_workspace();
    test_tool_register();
    test_tool_register_multiple();
    test_tool_execute();
    test_tool_execute_error();
    test_tool_execute_not_found();
    test_tool_definitions_json();
    test_tool_definitions_empty();
    test_tool_result_free();

    printf("\n-- Providers --\n");
    test_provider_create_anthropic();
    test_provider_create_openai();
    test_provider_create_ollama();
    test_provider_create_google();
    test_provider_create_bedrock();
    test_provider_free_null();
    test_completion_free();

    printf("\n-- Sandbox --\n");
    test_sandbox_defaults();
    test_sandbox_create();
    test_sandbox_available();

    printf("\n-- Agent --\n");
    test_agent_create();
    test_agent_reset();

    printf("\n=== All libclawd-agents tests passed ===\n");
    return 0;
}
