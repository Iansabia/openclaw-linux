/*
 * kelp-linux :: libkelp-agents
 * tools/file_read.c - File read tool
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/tool.h>
#include <kelp/json.h>
#include <kelp/buf.h>
#include <kelp/str.h>
#include <kelp/log.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#define FILE_READ_NAME        "file_read"
#define FILE_READ_DESCRIPTION "Read the contents of a file. Supports optional line range."
#define FILE_READ_PARAMS \
    "{\"type\":\"object\"," \
    "\"properties\":{" \
        "\"file_path\":{\"type\":\"string\",\"description\":\"Absolute path to the file to read\"}," \
        "\"offset\":{\"type\":\"integer\",\"description\":\"Line number to start reading from (1-based, default 1)\"}," \
        "\"limit\":{\"type\":\"integer\",\"description\":\"Maximum number of lines to read (default: all)\"}" \
    "}," \
    "\"required\":[\"file_path\"]}"

static int file_read_exec(kelp_tool_ctx_t *ctx, const char *args_json,
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

    const char *file_path = kelp_json_get_string(args, "file_path");
    if (!file_path) {
        result->output   = strdup("error: 'file_path' parameter is required");
        result->is_error = true;
        result->exit_code = -1;
        cJSON_Delete(args);
        return -1;
    }

    int offset = kelp_json_get_int(args, "offset", 1);
    int limit  = kelp_json_get_int(args, "limit", 0);  /* 0 = all */

    if (offset < 1) offset = 1;

    KELP_DEBUG("file_read: %s (offset=%d, limit=%d)", file_path, offset, limit);

    /* Read the file */
    FILE *fp = fopen(file_path, "r");
    if (!fp) {
        kelp_str_t err = kelp_str_new();
        kelp_str_printf(&err, "error: cannot open file '%s': %s",
                         file_path, strerror(errno));
        result->output   = err.data ? strdup(err.data) : strdup("error: cannot open file");
        result->is_error = true;
        result->exit_code = 1;
        kelp_str_free(&err);
        cJSON_Delete(args);
        return 0;
    }

    kelp_str_t out = kelp_str_new();
    char line_buf[8192];
    int line_num = 0;
    int lines_read = 0;

    while (fgets(line_buf, sizeof(line_buf), fp)) {
        line_num++;

        if (line_num < offset) continue;

        if (limit > 0 && lines_read >= limit) break;

        /* Prefix with line number */
        kelp_str_t numbered = kelp_str_new();
        kelp_str_printf(&numbered, "%6d\t%s", line_num, line_buf);
        if (numbered.data) {
            kelp_str_append_cstr(&out, numbered.data);
        }
        kelp_str_free(&numbered);
        lines_read++;
    }

    fclose(fp);

    if (out.len == 0) {
        result->output = strdup("(empty file or range out of bounds)");
    } else {
        result->output = out.data ? strdup(out.data) : strdup("");
    }

    result->is_error  = false;
    result->exit_code = 0;

    kelp_str_free(&out);
    cJSON_Delete(args);
    return 0;
}

/* ---- Registration ------------------------------------------------------- */

const kelp_tool_def_t kelp_file_read_tool_def = {
    .name                 = FILE_READ_NAME,
    .description          = FILE_READ_DESCRIPTION,
    .params_json          = FILE_READ_PARAMS,
    .exec                 = file_read_exec,
    .requires_sandbox     = false,
    .requires_confirmation = false
};
