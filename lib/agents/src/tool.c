/*
 * clawd-linux :: libclawd-agents
 * tool.c - Tool context, registration, execution, and JSON definition generation
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/tool.h>
#include <clawd/json.h>
#include <clawd/str.h>
#include <clawd/map.h>
#include <clawd/log.h>

#include <stdlib.h>
#include <string.h>

/* ---- Internal tool registration entry ----------------------------------- */

typedef struct tool_entry {
    char               *name;
    char               *description;
    char               *params_json;
    clawd_tool_exec_fn  exec;
    bool                requires_sandbox;
    bool                requires_confirmation;
} tool_entry_t;

/* ---- Tool context ------------------------------------------------------- */

struct clawd_tool_ctx {
    char        *workspace_dir;
    clawd_map_t *tools;           /* name -> tool_entry_t* */
    int          tool_count;
};

/* ---- External tool definitions (from tools/*.c) ------------------------- */

extern const clawd_tool_def_t clawd_bash_tool_def;
extern const clawd_tool_def_t clawd_file_read_tool_def;
extern const clawd_tool_def_t clawd_file_write_tool_def;
extern const clawd_tool_def_t clawd_web_fetch_tool_def;

/* ---- Tool context lifecycle --------------------------------------------- */

clawd_tool_ctx_t *clawd_tool_ctx_new(const char *workspace_dir)
{
    clawd_tool_ctx_t *ctx = (clawd_tool_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    if (workspace_dir) {
        ctx->workspace_dir = strdup(workspace_dir);
    }

    ctx->tools = clawd_map_new();
    if (!ctx->tools) {
        free(ctx->workspace_dir);
        free(ctx);
        return NULL;
    }

    ctx->tool_count = 0;
    return ctx;
}

static void free_tool_entry(tool_entry_t *entry)
{
    if (!entry) return;
    free(entry->name);
    free(entry->description);
    free(entry->params_json);
    free(entry);
}

void clawd_tool_ctx_free(clawd_tool_ctx_t *ctx)
{
    if (!ctx) return;

    /* Free all tool entries via map iteration */
    if (ctx->tools) {
        clawd_map_iter_t it = {0};
        while (clawd_map_iter(ctx->tools, &it)) {
            free_tool_entry((tool_entry_t *)it.value);
        }
        clawd_map_free(ctx->tools);
    }

    free(ctx->workspace_dir);
    free(ctx);
}

/* ---- Registration ------------------------------------------------------- */

int clawd_tool_register(clawd_tool_ctx_t *ctx, const clawd_tool_def_t *def)
{
    if (!ctx || !def || !def->name || !def->exec) return -1;

    /* Check for duplicate */
    if (clawd_map_has(ctx->tools, def->name)) {
        CLAWD_WARN("tool: '%s' already registered, replacing", def->name);
        tool_entry_t *old = (tool_entry_t *)clawd_map_get(ctx->tools, def->name);
        free_tool_entry(old);
        clawd_map_del(ctx->tools, def->name);
        ctx->tool_count--;
    }

    tool_entry_t *entry = (tool_entry_t *)calloc(1, sizeof(*entry));
    if (!entry) return -1;

    entry->name        = strdup(def->name);
    entry->description = def->description ? strdup(def->description) : strdup("");
    entry->params_json = def->params_json ? strdup(def->params_json) : strdup("{}");
    entry->exec        = def->exec;
    entry->requires_sandbox     = def->requires_sandbox;
    entry->requires_confirmation = def->requires_confirmation;

    if (!entry->name) {
        free_tool_entry(entry);
        return -1;
    }

    if (clawd_map_set(ctx->tools, entry->name, entry) != 0) {
        free_tool_entry(entry);
        return -1;
    }

    ctx->tool_count++;
    CLAWD_DEBUG("tool: registered '%s'", def->name);
    return 0;
}

/* ---- Execution ---------------------------------------------------------- */

int clawd_tool_execute(clawd_tool_ctx_t *ctx, const char *name,
                       const char *args_json, clawd_tool_result_t *result)
{
    if (!ctx || !name || !result) return -1;

    memset(result, 0, sizeof(*result));

    tool_entry_t *entry = (tool_entry_t *)clawd_map_get(ctx->tools, name);
    if (!entry) {
        clawd_str_t err = clawd_str_new();
        clawd_str_printf(&err, "error: unknown tool '%s'", name);
        result->output   = err.data ? strdup(err.data) : strdup("error: unknown tool");
        result->is_error = true;
        result->exit_code = -1;
        clawd_str_free(&err);
        return -1;
    }

    CLAWD_DEBUG("tool: executing '%s'", name);

    int rc = entry->exec(ctx, args_json ? args_json : "{}", result);
    return rc;
}

/* ---- JSON definitions --------------------------------------------------- */

/*
 * Generate a JSON array of tool definitions in the Anthropic format:
 * [
 *   {
 *     "name": "...",
 *     "description": "...",
 *     "input_schema": { ... }
 *   },
 *   ...
 * ]
 */
char *clawd_tool_get_definitions_json(clawd_tool_ctx_t *ctx)
{
    if (!ctx) return NULL;

    cJSON *array = cJSON_CreateArray();
    if (!array) return NULL;

    clawd_map_iter_t it = {0};
    while (clawd_map_iter(ctx->tools, &it)) {
        tool_entry_t *entry = (tool_entry_t *)it.value;
        if (!entry) continue;

        cJSON *tool = cJSON_CreateObject();
        if (!tool) continue;

        cJSON_AddStringToObject(tool, "name", entry->name);
        cJSON_AddStringToObject(tool, "description", entry->description);

        /* Parse the params JSON schema */
        cJSON *schema = cJSON_Parse(entry->params_json);
        if (schema) {
            cJSON_AddItemToObject(tool, "input_schema", schema);
        } else {
            cJSON_AddItemToObject(tool, "input_schema", cJSON_CreateObject());
        }

        cJSON_AddItemToArray(array, tool);
    }

    char *json_str = cJSON_PrintUnformatted(array);
    cJSON_Delete(array);
    return json_str;
}

/* ---- Result cleanup ----------------------------------------------------- */

void clawd_tool_result_free(clawd_tool_result_t *result)
{
    if (!result) return;
    free(result->output);
    result->output    = NULL;
    result->is_error  = false;
    result->exit_code = 0;
}

/* ---- Default tools ------------------------------------------------------ */

int clawd_tool_register_defaults(clawd_tool_ctx_t *ctx)
{
    if (!ctx) return -1;

    int rc = 0;
    rc |= clawd_tool_register(ctx, &clawd_bash_tool_def);
    rc |= clawd_tool_register(ctx, &clawd_file_read_tool_def);
    rc |= clawd_tool_register(ctx, &clawd_file_write_tool_def);
    rc |= clawd_tool_register(ctx, &clawd_web_fetch_tool_def);

    if (rc != 0) {
        CLAWD_WARN("tool: some default tools failed to register");
    }

    return rc;
}
