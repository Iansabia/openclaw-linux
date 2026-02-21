/*
 * kelp-linux :: libkelp-agents
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

#include <kelp/agent.h>
#include <kelp/provider.h>
#include <kelp/tool.h>
#include <kelp/log.h>
#include <kelp/str.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_MAX_TURNS  10

/* ---- Agent state -------------------------------------------------------- */

struct kelp_agent {
    kelp_provider_t *provider;
    kelp_tool_ctx_t *tools;
    char             *system_prompt;
    char             *model;
    int               max_tokens;
    int               max_turns;
    bool              sandbox_tools;
    kelp_stream_cb   on_stream;
    void             *stream_userdata;
    kelp_message_t  *history;       /* linked list of all messages */
};

/* ---- Helper: deep copy a message ---------------------------------------- */

static kelp_message_t *message_dup(const kelp_message_t *src)
{
    if (!src) return NULL;

    kelp_message_t *dst = kelp_message_new(src->role, src->content);
    if (!dst) return NULL;

    if (src->tool_call_id) dst->tool_call_id = strdup(src->tool_call_id);
    if (src->tool_name)    dst->tool_name    = strdup(src->tool_name);
    if (src->tool_args)    dst->tool_args    = strdup(src->tool_args);

    return dst;
}

/* ---- Agent lifecycle ---------------------------------------------------- */

kelp_agent_t *kelp_agent_new(const kelp_agent_opts_t *opts)
{
    if (!opts || !opts->provider) return NULL;

    kelp_agent_t *a = (kelp_agent_t *)calloc(1, sizeof(*a));
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
    a->max_tokens = opts->max_tokens;

    a->history = NULL;
    return a;
}

void kelp_agent_free(kelp_agent_t *a)
{
    if (!a) return;

    kelp_message_free(a->history);
    free(a->system_prompt);
    free(a->model);
    free(a);
}

void kelp_agent_reset(kelp_agent_t *a)
{
    if (!a) return;

    kelp_message_free(a->history);
    a->history = NULL;
}

kelp_message_t *kelp_agent_get_history(kelp_agent_t *a)
{
    if (!a) return NULL;
    return a->history;
}

int kelp_agent_set_history(kelp_agent_t *a, const kelp_message_t *msgs)
{
    if (!a) return -1;

    /* Build new list first so history is unchanged on failure */
    kelp_message_t *new_list = NULL;
    kelp_message_t **tail    = &new_list;

    for (const kelp_message_t *src = msgs; src; src = src->next) {
        kelp_message_t *copy = message_dup(src);
        if (!copy) {
            kelp_message_free(new_list);
            return -1;
        }
        *tail = copy;
        tail  = &copy->next;
    }

    kelp_message_free(a->history);
    a->history = new_list;
    return 0;
}

/* ---- Agent chat loop ---------------------------------------------------- */

int kelp_agent_chat(kelp_agent_t *a, const char *user_message, char **response)
{
    if (!a || !user_message || !response) return -1;

    *response = NULL;

    /* Step 1: Append user message to history */
    kelp_message_t *user_msg = kelp_message_new(KELP_ROLE_USER, user_message);
    if (!user_msg) return -1;
    kelp_message_append(&a->history, user_msg);

    /* Get tool definitions JSON */
    char *tools_json = NULL;
    if (a->tools) {
        tools_json = kelp_tool_get_definitions_json(a->tools);
    }

    int turn = 0;

    while (turn < a->max_turns) {
        turn++;
        KELP_DEBUG("agent: turn %d/%d", turn, a->max_turns);

        /* Build completion options */
        kelp_completion_opts_t opts = {0};
        opts.model         = a->model;
        opts.max_tokens    = a->max_tokens;
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
        kelp_completion_t completion = {0};
        int rc = kelp_provider_complete(a->provider, &opts, &completion);

        if (rc != 0) {
            KELP_ERROR("agent: provider completion failed on turn %d", turn);
            kelp_completion_free(&completion);
            free(tools_json);
            return -1;
        }

        KELP_DEBUG("agent: stop_reason=%s, tokens=%d/%d",
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
                kelp_message_t *asst = kelp_message_new(KELP_ROLE_ASSISTANT,
                                                           completion.content);
                if (asst) {
                    kelp_message_append(&a->history, asst);
                }
            }

            for (kelp_message_t *tc = completion.tool_calls; tc; tc = tc->next) {
                /* Add assistant tool_use message to history */
                kelp_message_t *asst_tc = message_dup(tc);
                if (asst_tc) {
                    kelp_message_append(&a->history, asst_tc);
                }

                /* Execute the tool */
                kelp_tool_result_t tool_result = {0};
                int exec_rc = -1;

                if (a->tools && tc->tool_name) {
                    KELP_INFO("agent: calling tool '%s'", tc->tool_name);
                    exec_rc = kelp_tool_execute(a->tools, tc->tool_name,
                                                  tc->tool_args, &tool_result);
                } else {
                    tool_result.output = strdup("error: tool execution not available");
                    tool_result.is_error = true;
                }

                /* Add tool result to history */
                const char *output = tool_result.output ? tool_result.output : "";
                kelp_message_t *result_msg = kelp_message_new(KELP_ROLE_TOOL, output);
                if (result_msg) {
                    if (tc->tool_call_id) {
                        result_msg->tool_call_id = strdup(tc->tool_call_id);
                    }
                    if (tc->tool_name) {
                        result_msg->tool_name = strdup(tc->tool_name);
                    }
                    kelp_message_append(&a->history, result_msg);
                }

                (void)exec_rc;
                kelp_tool_result_free(&tool_result);
            }

            kelp_completion_free(&completion);
            /* Continue the loop to send tool results back to the provider */
            continue;

        } else {
            /*
             * end_turn or max_tokens: return the assistant's response.
             */

            /* Add assistant message to history */
            if (completion.content) {
                kelp_message_t *asst = kelp_message_new(KELP_ROLE_ASSISTANT,
                                                           completion.content);
                if (asst) {
                    kelp_message_append(&a->history, asst);
                }

                *response = strdup(completion.content);
            } else {
                *response = strdup("");
            }

            kelp_completion_free(&completion);
            free(tools_json);
            return 0;
        }
    }

    /* Exhausted max_turns */
    KELP_WARN("agent: reached max turns (%d) without final response", a->max_turns);
    *response = strdup("[reached maximum tool-use iterations]");
    free(tools_json);
    return 0;
}
