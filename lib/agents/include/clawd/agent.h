/*
 * clawd-linux :: libclawd-agents
 * agent.h - Agent session loop (provider + tools + conversation management)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_AGENT_H
#define CLAWD_AGENT_H

#include <clawd/provider.h>
#include <clawd/tool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Opaque handle ------------------------------------------------------ */

typedef struct clawd_agent clawd_agent_t;

/* ---- Agent options ------------------------------------------------------ */

typedef struct clawd_agent_opts {
    clawd_provider_t *provider;
    clawd_tool_ctx_t *tools;
    const char       *system_prompt;
    const char       *model;            /* model name (passed to provider) */
    int               max_turns;         /* max tool-use iterations (default 10) */
    bool              sandbox_tools;     /* run tools in sandbox */
    clawd_stream_cb   on_stream;         /* streaming output callback */
    void             *stream_userdata;
} clawd_agent_opts_t;

/* ---- API ---------------------------------------------------------------- */

/**
 * Create a new agent session.
 *
 * @param opts  Agent options.  The provider and tools handles are borrowed
 *              (not owned) -- the caller must keep them alive for the
 *              lifetime of the agent.
 * @return Agent handle, or NULL on allocation failure.
 */
clawd_agent_t *clawd_agent_new(const clawd_agent_opts_t *opts);

/**
 * Free an agent and all owned conversation history.
 *
 * @param a  Agent handle (may be NULL).
 */
void clawd_agent_free(clawd_agent_t *a);

/**
 * Send a user message and get an assistant response.
 *
 * This runs the full agent loop:
 *   1. Append the user message to history.
 *   2. Call the provider with the conversation + tools.
 *   3. If the provider requests tool use, execute the tools, add results
 *      to history, and loop back to step 2.
 *   4. If the provider returns an end_turn, set *response to the assistant's
 *      text and return.
 *   5. The loop is bounded by max_turns to prevent infinite tool use.
 *
 * @param a         Agent handle.
 * @param user_message  The user's input text.
 * @param response  Output: a malloc'd string containing the final assistant
 *                  response.  The caller must free it.
 * @return 0 on success, -1 on error.
 */
int clawd_agent_chat(clawd_agent_t *a, const char *user_message, char **response);

/**
 * Reset the agent's conversation history.
 *
 * @param a  Agent handle.
 */
void clawd_agent_reset(clawd_agent_t *a);

/**
 * Get a read-only pointer to the current conversation history.
 *
 * The returned list must NOT be freed by the caller.
 *
 * @param a  Agent handle.
 * @return Head of the message linked list (may be NULL if empty).
 */
clawd_message_t *clawd_agent_get_history(clawd_agent_t *a);

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_AGENT_H */
