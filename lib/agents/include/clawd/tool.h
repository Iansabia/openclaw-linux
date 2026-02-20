/*
 * clawd-linux :: libclawd-agents
 * tool.h - Tool interface for agent tool execution
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_TOOL_H
#define CLAWD_TOOL_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Tool result -------------------------------------------------------- */

typedef struct clawd_tool_result {
    char *output;
    bool  is_error;
    int   exit_code;
} clawd_tool_result_t;

/* ---- Tool context (opaque) ---------------------------------------------- */

typedef struct clawd_tool_ctx clawd_tool_ctx_t;

/* ---- Tool execution function -------------------------------------------- */

/**
 * Tool execution callback.
 *
 * @param ctx        Tool context.
 * @param args_json  JSON string of tool arguments.
 * @param result     Output: populated on completion.
 * @return 0 on success, -1 on error.
 */
typedef int (*clawd_tool_exec_fn)(clawd_tool_ctx_t *ctx,
                                   const char *args_json,
                                   clawd_tool_result_t *result);

/* ---- Tool definition ---------------------------------------------------- */

typedef struct clawd_tool_def {
    const char         *name;
    const char         *description;
    const char         *params_json;       /* JSON Schema for parameters */
    clawd_tool_exec_fn  exec;
    bool                requires_sandbox;
    bool                requires_confirmation;
} clawd_tool_def_t;

/* ---- API ---------------------------------------------------------------- */

/**
 * Create a new tool context.
 *
 * @param workspace_dir  Base directory for file operations (copied internally).
 * @return Tool context, or NULL on allocation failure.
 */
clawd_tool_ctx_t *clawd_tool_ctx_new(const char *workspace_dir);

/**
 * Free a tool context and all registered tool definitions.
 *
 * @param ctx  Tool context (may be NULL).
 */
void clawd_tool_ctx_free(clawd_tool_ctx_t *ctx);

/**
 * Register a tool definition with the context.
 *
 * The definition's string fields (name, description, params_json) are
 * copied internally.  The exec function pointer is stored directly.
 *
 * @param ctx  Tool context.
 * @param def  Tool definition.
 * @return 0 on success, -1 on error.
 */
int clawd_tool_register(clawd_tool_ctx_t *ctx, const clawd_tool_def_t *def);

/**
 * Execute a registered tool by name.
 *
 * @param ctx        Tool context.
 * @param name       Tool name.
 * @param args_json  JSON string of tool arguments.
 * @param result     Output: populated on completion.
 * @return 0 on success, -1 if tool not found or execution error.
 */
int clawd_tool_execute(clawd_tool_ctx_t *ctx, const char *name,
                       const char *args_json, clawd_tool_result_t *result);

/**
 * Get all registered tool definitions as a JSON array string.
 *
 * The returned string is suitable for passing to providers in the
 * tools_json field of completion options.
 *
 * @param ctx  Tool context.
 * @return JSON array string (caller must free), or NULL on error.
 */
char *clawd_tool_get_definitions_json(clawd_tool_ctx_t *ctx);

/**
 * Free the dynamically allocated fields of a tool result.
 *
 * @param result  Tool result (may be NULL).
 */
void clawd_tool_result_free(clawd_tool_result_t *result);

/**
 * Register the default set of built-in tools: bash, file_read, file_write,
 * web_fetch.
 *
 * @param ctx  Tool context.
 * @return 0 on success, -1 on error.
 */
int clawd_tool_register_defaults(clawd_tool_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_TOOL_H */
