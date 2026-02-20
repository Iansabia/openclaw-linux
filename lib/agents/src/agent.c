/*
 * clawd-linux :: libclawd-agents
 * agent.c - Agent session loop
 *
 * Implements the agentic loop:
 *   1. Send conversation history + tools to provider.
 *   2. If provider requests tool_use, execute tools, add results, loop.
 *   3. If provider returns end_turn or max_tokens, return the response.
 *   4. Bounded by max_turns to prevent infinite tool loops.
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/agent.h>
#include <clawd/provider.h>
#include <clawd/tool.h>
#include <clawd/log.h>
#include <clawd/str.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_MAX_TURNS  10

/* ---- Agent state -------------------------------------------------------- */

struct clawd_agent {
    clawd_provider_t *provider;
    clawd_tool_ctx_t *tools;
    char             *system_prompt;
    char             *model;
    int               max_turns;
    bool              sandbox_tools;
    clawd_stream_cb   on_stream;
    void             *stream_userdata;
    clawd_message_t  *history;       /* linked list of all messages */
};

/* ---- Helper: deep copy a message ---------------------------------------- */

static clawd_message_t *message_dup(const clawd_message_t *src)
{
    if (!src) return NULL;

    clawd_message_t *dst = clawd_message_new(src->role, src->content);
    if (!dst) return NULL;

    if (src->tool_call_id) dst->tool_call_id = strdup(src->tool_call_id);
    if (src->tool_name)    dst->tool_name    = strdup(src->tool_name);
    if (src->tool_args)    dst->tool_args    = strdup(src->tool_args);

    return dst;
}

/* ---- Agent lifecycle ---------------------------------------------------- */

clawd_agent_t *clawd_agent_new(const clawd_agent_opts_t *opts)
{
    if (!opts || !opts->provider) return NULL;

    clawd_agent_t *a = (clawd_agent_t *)calloc(1, sizeof(*a));
    if (!a) return NULL;

    a->provider       = opts->provider;
    a->tools          = opts->tools;
    a->max_turns      = opts->max_turns > 0 ? opts->max_turns : DEFAULT_MAX_TURNS;
    a->sandbox_tools  = opts->sandbox_tools;
    a->on_stream      = opts->on_stream;
    a->stream_userdata = opts->stream_userdata;

    if (opts->system_prompt) {
        a->system_prompt = strdup(opts->system_prompt);
    }
    if (opts->model) {
        a->model = strdup(opts->model);
    }

    a->history = NULL;
    return a;
}

void clawd_agent_free(clawd_agent_t *a)
{
    if (!a) return;

    clawd_message_free(a->history);
    free(a->system_prompt);
    free(a->model);
    free(a);
}

void clawd_agent_reset(clawd_agent_t *a)
{
    if (!a) return;

    clawd_message_free(a->history);
    a->history = NULL;
}

clawd_message_t *clawd_agent_get_history(clawd_agent_t *a)
{
    if (!a) return NULL;
    return a->history;
}

/* ---- Agent chat loop ---------------------------------------------------- */

int clawd_agent_chat(clawd_agent_t *a, const char *user_message, char **response)
{
    if (!a || !user_message || !response) return -1;

    *response = NULL;

    /* Step 1: Append user message to history */
    clawd_message_t *user_msg = clawd_message_new(CLAWD_ROLE_USER, user_message);
    if (!user_msg) return -1;
    clawd_message_append(&a->history, user_msg);

    /* Get tool definitions JSON */
    char *tools_json = NULL;
    if (a->tools) {
        tools_json = clawd_tool_get_definitions_json(a->tools);
    }

    int turn = 0;

    while (turn < a->max_turns) {
        turn++;
        CLAWD_DEBUG("agent: turn %d/%d", turn, a->max_turns);

        /* Build completion options */
        clawd_completion_opts_t opts = {0};
        opts.model         = a->model;
        opts.messages      = a->history;
        opts.system_prompt = a->system_prompt;
        opts.tools_json    = tools_json;
        opts.temperature   = 0.0f;  /* default: deterministic */

        if (a->on_stream) {
            opts.stream          = true;
            opts.stream_cb       = a->on_stream;
            opts.stream_userdata = a->stream_userdata;
        }

        /* Step 2: Call the provider */
        clawd_completion_t completion = {0};
        int rc = clawd_provider_complete(a->provider, &opts, &completion);

        if (rc != 0) {
            CLAWD_ERROR("agent: provider completion failed on turn %d", turn);
            clawd_completion_free(&completion);
            free(tools_json);
            return -1;
        }

        CLAWD_DEBUG("agent: stop_reason=%s, tokens=%d/%d",
                    completion.stop_reason ? completion.stop_reason : "?",
                    completion.input_tokens, completion.output_tokens);

        /* Step 3: Handle the response based on stop_reason */

        if (completion.stop_reason &&
            strcmp(completion.stop_reason, "tool_use") == 0 &&
            completion.tool_calls) {
            /*
             * Tool use: execute each tool call and add results to history.
             *
             * For each tool call:
             *   1. Add assistant message with tool_use to history
             *   2. Execute the tool
             *   3. Add tool result message to history
             */

            /* Add assistant message(s) with text content if any */
            if (completion.content && *completion.content) {
                clawd_message_t *asst = clawd_message_new(CLAWD_ROLE_ASSISTANT,
                                                           completion.content);
                if (asst) {
                    clawd_message_append(&a->history, asst);
                }
            }

            for (clawd_message_t *tc = completion.tool_calls; tc; tc = tc->next) {
                /* Add assistant tool_use message to history */
                clawd_message_t *asst_tc = message_dup(tc);
                if (asst_tc) {
                    clawd_message_append(&a->history, asst_tc);
                }

                /* Execute the tool */
                clawd_tool_result_t tool_result = {0};
                int exec_rc = -1;

                if (a->tools && tc->tool_name) {
                    CLAWD_INFO("agent: calling tool '%s'", tc->tool_name);
                    exec_rc = clawd_tool_execute(a->tools, tc->tool_name,
                                                  tc->tool_args, &tool_result);
                } else {
                    tool_result.output = strdup("error: tool execution not available");
                    tool_result.is_error = true;
                }

                /* Add tool result to history */
                const char *output = tool_result.output ? tool_result.output : "";
                clawd_message_t *result_msg = clawd_message_new(CLAWD_ROLE_TOOL, output);
                if (result_msg) {
                    if (tc->tool_call_id) {
                        result_msg->tool_call_id = strdup(tc->tool_call_id);
                    }
                    if (tc->tool_name) {
                        result_msg->tool_name = strdup(tc->tool_name);
                    }
                    clawd_message_append(&a->history, result_msg);
                }

                (void)exec_rc;
                clawd_tool_result_free(&tool_result);
            }

            clawd_completion_free(&completion);
            /* Continue the loop to send tool results back to the provider */
            continue;

        } else {
            /*
             * end_turn or max_tokens: return the assistant's response.
             */

            /* Add assistant message to history */
            if (completion.content) {
                clawd_message_t *asst = clawd_message_new(CLAWD_ROLE_ASSISTANT,
                                                           completion.content);
                if (asst) {
                    clawd_message_append(&a->history, asst);
                }

                *response = strdup(completion.content);
            } else {
                *response = strdup("");
            }

            clawd_completion_free(&completion);
            free(tools_json);
            return 0;
        }
    }

    /* Exhausted max_turns */
    CLAWD_WARN("agent: reached max turns (%d) without final response", a->max_turns);
    *response = strdup("[reached maximum tool-use iterations]");
    free(tools_json);
    return 0;
}
