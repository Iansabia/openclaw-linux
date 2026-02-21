/*
 * kelp-linux :: libkelp-agents
 * tool.h - Tool interface for agent tool execution
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_TOOL_H
#define KELP_TOOL_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Tool result -------------------------------------------------------- */

typedef struct kelp_tool_result {
    char *output;
    bool  is_error;
    int   exit_code;
} kelp_tool_result_t;

/* ---- Tool context (opaque) ---------------------------------------------- */

typedef struct kelp_tool_ctx kelp_tool_ctx_t;

/* ---- Tool execution function -------------------------------------------- */

/**
 * Tool execution callback.
 *
 * @param ctx        Tool context.
 * @param args_json  JSON string of tool arguments.
 * @param result     Output: populated on completion.
 * @return 0 on success, -1 on error.
 */
typedef int (*kelp_tool_exec_fn)(kelp_tool_ctx_t *ctx,
                                   const char *args_json,
                                   kelp_tool_result_t *result);

/* ---- Tool definition ---------------------------------------------------- */

typedef struct kelp_tool_def {
    const char         *name;
    const char         *description;
    const char         *params_json;       /* JSON Schema for parameters */
    kelp_tool_exec_fn  exec;
    bool                requires_sandbox;
    bool                requires_confirmation;
} kelp_tool_def_t;

/* ---- API ---------------------------------------------------------------- */

/**
 * Create a new tool context.
 *
 * @param workspace_dir  Base directory for file operations (copied internally).
 * @return Tool context, or NULL on allocation failure.
 */
kelp_tool_ctx_t *kelp_tool_ctx_new(const char *workspace_dir);

/**
 * Free a tool context and all registered tool definitions.
 *
 * @param ctx  Tool context (may be NULL).
 */
void kelp_tool_ctx_free(kelp_tool_ctx_t *ctx);

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
int kelp_tool_register(kelp_tool_ctx_t *ctx, const kelp_tool_def_t *def);

/**
 * Execute a registered tool by name.
 *
 * @param ctx        Tool context.
 * @param name       Tool name.
 * @param args_json  JSON string of tool arguments.
 * @param result     Output: populated on completion.
 * @return 0 on success, -1 if tool not found or execution error.
 */
int kelp_tool_execute(kelp_tool_ctx_t *ctx, const char *name,
                       const char *args_json, kelp_tool_result_t *result);

/**
 * Get all registered tool definitions as a JSON array string.
 *
 * The returned string is suitable for passing to providers in the
 * tools_json field of completion options.
 *
 * @param ctx  Tool context.
 * @return JSON array string (caller must free), or NULL on error.
 */
char *kelp_tool_get_definitions_json(kelp_tool_ctx_t *ctx);

/**
 * Free the dynamically allocated fields of a tool result.
 *
 * @param result  Tool result (may be NULL).
 */
void kelp_tool_result_free(kelp_tool_result_t *result);

/**
 * Register the default set of built-in tools: bash, file_read, file_write,
 * web_fetch.
 *
 * @param ctx  Tool context.
 * @return 0 on success, -1 on error.
 */
int kelp_tool_register_defaults(kelp_tool_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* KELP_TOOL_H */
