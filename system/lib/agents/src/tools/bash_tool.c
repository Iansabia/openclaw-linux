/*
 * kelp-linux :: libkelp-agents
 * tools/bash_tool.c - Bash command execution tool
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/tool.h>
#include <kelp/process.h>
#include <kelp/json.h>
#include <kelp/str.h>
#include <kelp/log.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define BASH_TOOL_NAME        "bash"
#define BASH_TOOL_DESCRIPTION "Execute a bash command and return its output."
#define BASH_TOOL_PARAMS \
    "{\"type\":\"object\"," \
    "\"properties\":{" \
        "\"command\":{\"type\":\"string\",\"description\":\"The bash command to execute\"}," \
        "\"timeout\":{\"type\":\"integer\",\"description\":\"Timeout in milliseconds (default 30000)\"}" \
    "}," \
    "\"required\":[\"command\"]}"

#define DEFAULT_TIMEOUT_MS  30000

static int bash_exec(kelp_tool_ctx_t *ctx, const char *args_json,
                     kelp_tool_result_t *result)
{
    if (!result) return -1;

    memset(result, 0, sizeof(*result));

    /* Parse arguments */
    cJSON *args = cJSON_Parse(args_json);
    if (!args) {
        result->output   = strdup("error: invalid JSON arguments");
        result->is_error = true;
        result->exit_code = -1;
        return -1;
    }

    const char *command = kelp_json_get_string(args, "command");
    if (!command) {
        result->output   = strdup("error: 'command' parameter is required");
        result->is_error = true;
        result->exit_code = -1;
        cJSON_Delete(args);
        return -1;
    }

    int timeout_ms = kelp_json_get_int(args, "timeout", DEFAULT_TIMEOUT_MS);

    KELP_DEBUG("bash tool: executing: %s", command);

    /* Set up process options */
    char *const argv[] = {"/bin/bash", "-c", (char *)command, NULL};

    kelp_proc_opts_t opts = {0};
    opts.cmd            = "/bin/bash";
    opts.argv           = argv;
    opts.timeout_ms     = timeout_ms;
    opts.capture_stdout = true;
    opts.capture_stderr = true;
    opts.merge_stderr   = true;
    opts.set_pgid       = true;

    kelp_proc_result_t proc_result = {0};
    int rc = kelp_proc_exec(&opts, &proc_result);

    if (rc != 0) {
        result->output   = strdup("error: failed to execute command");
        result->is_error = true;
        result->exit_code = -1;
    } else {
        /* Build output string */
        kelp_str_t out = kelp_str_new();

        if (proc_result.stdout_data && proc_result.stdout_len > 0) {
            kelp_str_append(&out, proc_result.stdout_data, proc_result.stdout_len);
        }

        if (proc_result.timed_out) {
            kelp_str_append_cstr(&out, "\n[command timed out]");
        }

        result->output    = out.data ? strdup(out.data) : strdup("");
        result->exit_code = proc_result.exit_code;
        result->is_error  = (proc_result.exit_code != 0);

        kelp_str_free(&out);
    }

    kelp_proc_result_free(&proc_result);
    cJSON_Delete(args);
    return 0;
}

/* ---- Registration ------------------------------------------------------- */

const kelp_tool_def_t kelp_bash_tool_def = {
    .name                 = BASH_TOOL_NAME,
    .description          = BASH_TOOL_DESCRIPTION,
    .params_json          = BASH_TOOL_PARAMS,
    .exec                 = bash_exec,
    .requires_sandbox     = true,
    .requires_confirmation = true
};
