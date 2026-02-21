/*
 * kelp-linux :: libkelp-agents
 * test_agents.c - Unit tests for provider, tool, and agent APIs
 *
 * Tests message creation/linking, tool registration, tool definitions
 * JSON generation, and provider creation (without actual API calls).
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <kelp/provider.h>
#include <kelp/tool.h>
#include <kelp/agent.h>
#include <kelp/sandbox.h>

/* ---- Message tests ------------------------------------------------------ */

static void test_message_new(void)
{
    kelp_message_t *msg = kelp_message_new(KELP_ROLE_USER, "hello");
    assert(msg != NULL);
    assert(msg->role == KELP_ROLE_USER);
    assert(strcmp(msg->content, "hello") == 0);
    assert(msg->next == NULL);
    assert(msg->tool_call_id == NULL);
    assert(msg->tool_name == NULL);
    assert(msg->tool_args == NULL);
    kelp_message_free(msg);
    printf("  PASS: message_new\n");
}

static void test_message_new_null_content(void)
{
    kelp_message_t *msg = kelp_message_new(KELP_ROLE_ASSISTANT, NULL);
    assert(msg != NULL);
    assert(msg->role == KELP_ROLE_ASSISTANT);
    assert(msg->content == NULL);
    kelp_message_free(msg);
    printf("  PASS: message_new with NULL content\n");
}

static void test_message_append(void)
{
    kelp_message_t *list = NULL;

    kelp_message_t *m1 = kelp_message_new(KELP_ROLE_USER, "first");
    kelp_message_t *m2 = kelp_message_new(KELP_ROLE_ASSISTANT, "second");
    kelp_message_t *m3 = kelp_message_new(KELP_ROLE_USER, "third");

    kelp_message_append(&list, m1);
    assert(list == m1);
    assert(list->next == NULL);

    kelp_message_append(&list, m2);
    assert(list == m1);
    assert(list->next == m2);
    assert(m2->next == NULL);

    kelp_message_append(&list, m3);
    assert(list->next->next == m3);
    assert(m3->next == NULL);

    /* Verify traversal */
    int count = 0;
    for (kelp_message_t *m = list; m; m = m->next) count++;
    assert(count == 3);

    kelp_message_free(list);
    printf("  PASS: message_append linked list\n");
}

static void test_message_free_null(void)
{
    /* Should not crash */
    kelp_message_free(NULL);
    printf("  PASS: message_free NULL\n");
}

static void test_message_roles(void)
{
    kelp_message_t *m;

    m = kelp_message_new(KELP_ROLE_SYSTEM, "system prompt");
    assert(m->role == KELP_ROLE_SYSTEM);
    kelp_message_free(m);

    m = kelp_message_new(KELP_ROLE_TOOL, "tool result");
    assert(m->role == KELP_ROLE_TOOL);
    kelp_message_free(m);

    printf("  PASS: message roles\n");
}

static void test_message_tool_fields(void)
{
    kelp_message_t *msg = kelp_message_new(KELP_ROLE_ASSISTANT, NULL);
    assert(msg != NULL);

    msg->tool_call_id = strdup("call_123");
    msg->tool_name    = strdup("bash");
    msg->tool_args    = strdup("{\"command\":\"ls\"}");

    assert(strcmp(msg->tool_call_id, "call_123") == 0);
    assert(strcmp(msg->tool_name, "bash") == 0);
    assert(strcmp(msg->tool_args, "{\"command\":\"ls\"}") == 0);

    kelp_message_free(msg);
    printf("  PASS: message tool fields\n");
}

/* ---- Tool tests --------------------------------------------------------- */

static int dummy_tool_exec(kelp_tool_ctx_t *ctx, const char *args_json,
                           kelp_tool_result_t *result)
{
    (void)ctx;
    (void)args_json;
    result->output    = strdup("dummy output");
    result->is_error  = false;
    result->exit_code = 0;
    return 0;
}

static int error_tool_exec(kelp_tool_ctx_t *ctx, const char *args_json,
                           kelp_tool_result_t *result)
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
    kelp_tool_ctx_t *ctx = kelp_tool_ctx_new("/tmp/workspace");
    assert(ctx != NULL);
    kelp_tool_ctx_free(ctx);
    printf("  PASS: tool_ctx_new/free\n");
}

static void test_tool_ctx_null_workspace(void)
{
    kelp_tool_ctx_t *ctx = kelp_tool_ctx_new(NULL);
    assert(ctx != NULL);
    kelp_tool_ctx_free(ctx);
    printf("  PASS: tool_ctx_new with NULL workspace\n");
}

static void test_tool_register(void)
{
    kelp_tool_ctx_t *ctx = kelp_tool_ctx_new("/tmp");
    assert(ctx != NULL);

    kelp_tool_def_t def = {
        .name        = "test_tool",
        .description = "A test tool",
        .params_json = "{\"type\":\"object\",\"properties\":{}}",
        .exec        = dummy_tool_exec,
        .requires_sandbox     = false,
        .requires_confirmation = false
    };

    int rc = kelp_tool_register(ctx, &def);
    assert(rc == 0);

    kelp_tool_ctx_free(ctx);
    printf("  PASS: tool_register\n");
}

static void test_tool_register_multiple(void)
{
    kelp_tool_ctx_t *ctx = kelp_tool_ctx_new("/tmp");

    kelp_tool_def_t def1 = {
        .name = "tool_a", .description = "Tool A",
        .params_json = "{}", .exec = dummy_tool_exec
    };
    kelp_tool_def_t def2 = {
        .name = "tool_b", .description = "Tool B",
        .params_json = "{}", .exec = error_tool_exec
    };

    assert(kelp_tool_register(ctx, &def1) == 0);
    assert(kelp_tool_register(ctx, &def2) == 0);

    kelp_tool_ctx_free(ctx);
    printf("  PASS: tool_register multiple\n");
}

static void test_tool_execute(void)
{
    kelp_tool_ctx_t *ctx = kelp_tool_ctx_new("/tmp");

    kelp_tool_def_t def = {
        .name = "hello", .description = "Says hello",
        .params_json = "{}", .exec = dummy_tool_exec
    };
    kelp_tool_register(ctx, &def);

    kelp_tool_result_t result = {0};
    int rc = kelp_tool_execute(ctx, "hello", "{}", &result);
    assert(rc == 0);
    assert(result.output != NULL);
    assert(strcmp(result.output, "dummy output") == 0);
    assert(result.is_error == false);
    assert(result.exit_code == 0);

    kelp_tool_result_free(&result);
    kelp_tool_ctx_free(ctx);
    printf("  PASS: tool_execute\n");
}

static void test_tool_execute_error(void)
{
    kelp_tool_ctx_t *ctx = kelp_tool_ctx_new("/tmp");

    kelp_tool_def_t def = {
        .name = "fail", .description = "Fails",
        .params_json = "{}", .exec = error_tool_exec
    };
    kelp_tool_register(ctx, &def);

    kelp_tool_result_t result = {0};
    int rc = kelp_tool_execute(ctx, "fail", "{}", &result);
    assert(rc == 0);
    assert(result.is_error == true);
    assert(result.exit_code == 1);

    kelp_tool_result_free(&result);
    kelp_tool_ctx_free(ctx);
    printf("  PASS: tool_execute error tool\n");
}

static void test_tool_execute_not_found(void)
{
    kelp_tool_ctx_t *ctx = kelp_tool_ctx_new("/tmp");

    kelp_tool_result_t result = {0};
    int rc = kelp_tool_execute(ctx, "nonexistent", "{}", &result);
    assert(rc == -1);
    assert(result.is_error == true);
    assert(result.output != NULL);
    assert(strstr(result.output, "unknown tool") != NULL);

    kelp_tool_result_free(&result);
    kelp_tool_ctx_free(ctx);
    printf("  PASS: tool_execute not found\n");
}

static void test_tool_definitions_json(void)
{
    kelp_tool_ctx_t *ctx = kelp_tool_ctx_new("/tmp");

    kelp_tool_def_t def1 = {
        .name = "tool_alpha",
        .description = "First tool",
        .params_json = "{\"type\":\"object\",\"properties\":{\"x\":{\"type\":\"string\"}}}",
        .exec = dummy_tool_exec
    };
    kelp_tool_def_t def2 = {
        .name = "tool_beta",
        .description = "Second tool",
        .params_json = "{\"type\":\"object\",\"properties\":{}}",
        .exec = dummy_tool_exec
    };

    kelp_tool_register(ctx, &def1);
    kelp_tool_register(ctx, &def2);

    char *json = kelp_tool_get_definitions_json(ctx);
    assert(json != NULL);

    /* Should be a valid JSON array containing both tools */
    assert(json[0] == '[');
    assert(strstr(json, "tool_alpha") != NULL);
    assert(strstr(json, "tool_beta") != NULL);
    assert(strstr(json, "First tool") != NULL);
    assert(strstr(json, "Second tool") != NULL);
    assert(strstr(json, "input_schema") != NULL);

    free(json);
    kelp_tool_ctx_free(ctx);
    printf("  PASS: tool_definitions_json\n");
}

static void test_tool_definitions_empty(void)
{
    kelp_tool_ctx_t *ctx = kelp_tool_ctx_new("/tmp");

    char *json = kelp_tool_get_definitions_json(ctx);
    assert(json != NULL);
    assert(strcmp(json, "[]") == 0);

    free(json);
    kelp_tool_ctx_free(ctx);
    printf("  PASS: tool_definitions_json empty\n");
}

static void test_tool_result_free(void)
{
    kelp_tool_result_t result = {0};
    result.output = strdup("test");
    result.is_error = true;
    result.exit_code = 42;

    kelp_tool_result_free(&result);
    assert(result.output == NULL);
    assert(result.is_error == false);
    assert(result.exit_code == 0);

    /* Should not crash on NULL */
    kelp_tool_result_free(NULL);
    printf("  PASS: tool_result_free\n");
}

/* ---- Provider tests ----------------------------------------------------- */

static void test_provider_create_anthropic(void)
{
    kelp_provider_t *p = kelp_provider_new(KELP_PROVIDER_ANTHROPIC, "test-key");
    assert(p != NULL);
    assert(p->type == KELP_PROVIDER_ANTHROPIC);
    assert(p->api_key != NULL);
    assert(strcmp(p->api_key, "test-key") == 0);
    assert(p->complete != NULL);
    kelp_provider_free(p);
    printf("  PASS: provider_new anthropic\n");
}

static void test_provider_create_openai(void)
{
    kelp_provider_t *p = kelp_provider_new(KELP_PROVIDER_OPENAI, "sk-test");
    assert(p != NULL);
    assert(p->type == KELP_PROVIDER_OPENAI);
    assert(p->complete != NULL);
    kelp_provider_free(p);
    printf("  PASS: provider_new openai\n");
}

static void test_provider_create_ollama(void)
{
    kelp_provider_t *p = kelp_provider_new(KELP_PROVIDER_OLLAMA, NULL);
    assert(p != NULL);
    assert(p->type == KELP_PROVIDER_OLLAMA);
    assert(p->complete != NULL);
    kelp_provider_free(p);
    printf("  PASS: provider_new ollama\n");
}

static void test_provider_create_google(void)
{
    kelp_provider_t *p = kelp_provider_new(KELP_PROVIDER_GOOGLE, "google-key");
    assert(p != NULL);
    assert(p->type == KELP_PROVIDER_GOOGLE);
    assert(p->complete != NULL);
    kelp_provider_free(p);
    printf("  PASS: provider_new google\n");
}

static void test_provider_create_bedrock(void)
{
    kelp_provider_t *p = kelp_provider_new(KELP_PROVIDER_BEDROCK, NULL);
    assert(p != NULL);
    assert(p->type == KELP_PROVIDER_BEDROCK);
    assert(p->complete != NULL);
    assert(p->ctx != NULL);   /* bedrock creates its own context */
    kelp_provider_free(p);
    printf("  PASS: provider_new bedrock\n");
}

static void test_provider_free_null(void)
{
    kelp_provider_free(NULL);  /* should not crash */
    printf("  PASS: provider_free NULL\n");
}

static void test_completion_free(void)
{
    kelp_completion_t c = {0};
    c.content     = strdup("test response");
    c.stop_reason = strdup("end_turn");
    c.model       = strdup("claude-3");
    c.id          = strdup("msg_123");
    c.input_tokens  = 100;
    c.output_tokens = 50;

    kelp_completion_free(&c);
    assert(c.content == NULL);
    assert(c.stop_reason == NULL);
    assert(c.model == NULL);
    assert(c.id == NULL);
    assert(c.input_tokens == 0);
    assert(c.output_tokens == 0);

    /* Should handle NULL */
    kelp_completion_free(NULL);
    printf("  PASS: completion_free\n");
}

/* ---- Sandbox tests ------------------------------------------------------ */

static void test_sandbox_defaults(void)
{
    kelp_sandbox_opts_t opts;
    kelp_sandbox_default_opts(&opts);
    assert(opts.memory_limit_mb == 256);
    assert(opts.cpu_cores == 1);
    assert(opts.max_pids == 256);
    assert(opts.timeout_sec == 30);
    assert(opts.enable_network == false);
    printf("  PASS: sandbox_default_opts\n");
}

static void test_sandbox_create(void)
{
    kelp_sandbox_opts_t opts;
    kelp_sandbox_default_opts(&opts);
    opts.workspace = "/tmp";

    kelp_sandbox_t *sb = kelp_sandbox_new(&opts);
    assert(sb != NULL);
    kelp_sandbox_free(sb);
    printf("  PASS: sandbox_new/free\n");
}

static void test_sandbox_available(void)
{
    /* Just test that it doesn't crash */
    bool avail = kelp_sandbox_available();
    printf("  PASS: sandbox_available (result=%s)\n", avail ? "true" : "false");
}

/* ---- Agent tests -------------------------------------------------------- */

static void test_agent_create(void)
{
    kelp_provider_t *p = kelp_provider_new(KELP_PROVIDER_ANTHROPIC, "key");
    assert(p != NULL);

    kelp_tool_ctx_t *tools = kelp_tool_ctx_new("/tmp");
    assert(tools != NULL);

    kelp_agent_opts_t opts = {
        .provider      = p,
        .tools         = tools,
        .system_prompt = "You are a helpful assistant.",
        .max_turns     = 5
    };

    kelp_agent_t *a = kelp_agent_new(&opts);
    assert(a != NULL);

    /* History should be empty initially */
    kelp_message_t *hist = kelp_agent_get_history(a);
    assert(hist == NULL);

    kelp_agent_free(a);
    kelp_tool_ctx_free(tools);
    kelp_provider_free(p);
    printf("  PASS: agent_new/free\n");
}

static void test_agent_reset(void)
{
    kelp_provider_t *p = kelp_provider_new(KELP_PROVIDER_ANTHROPIC, "key");
    kelp_agent_opts_t opts = { .provider = p };
    kelp_agent_t *a = kelp_agent_new(&opts);
    assert(a != NULL);

    kelp_agent_reset(a);
    assert(kelp_agent_get_history(a) == NULL);

    kelp_agent_free(a);
    kelp_provider_free(p);
    printf("  PASS: agent_reset\n");
}

/* ---- Main --------------------------------------------------------------- */

int main(void)
{
    printf("=== libkelp-agents tests ===\n");

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

    printf("\n=== All libkelp-agents tests passed ===\n");
    return 0;
}
