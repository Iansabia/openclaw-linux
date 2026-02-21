/*
 * kelp-linux :: libkelp-agents
 * tools/file_write.c - File write tool
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/tool.h>
#include <kelp/json.h>
#include <kelp/str.h>
#include <kelp/log.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <libgen.h>

#define FILE_WRITE_NAME        "file_write"
#define FILE_WRITE_DESCRIPTION "Write content to a file, creating parent directories as needed."
#define FILE_WRITE_PARAMS \
    "{\"type\":\"object\"," \
    "\"properties\":{" \
        "\"file_path\":{\"type\":\"string\",\"description\":\"Absolute path to the file to write\"}," \
        "\"content\":{\"type\":\"string\",\"description\":\"Content to write to the file\"}" \
    "}," \
    "\"required\":[\"file_path\",\"content\"]}"

/*
 * Recursively create directories for a given path.
 * Similar to `mkdir -p`.
 */
static int mkdir_p(const char *path, mode_t mode)
{
    char *dup = strdup(path);
    if (!dup) return -1;

    char *p = dup;
    /* Skip leading slash */
    if (*p == '/') p++;

    while (*p) {
        /* Find next path separator */
        char *slash = strchr(p, '/');
        if (!slash) break;

        *slash = '\0';
        if (mkdir(dup, mode) != 0 && errno != EEXIST) {
            free(dup);
            return -1;
        }
        *slash = '/';
        p = slash + 1;
    }

    /* Create final directory */
    if (mkdir(dup, mode) != 0 && errno != EEXIST) {
        free(dup);
        return -1;
    }

    free(dup);
    return 0;
}

static int file_write_exec(kelp_tool_ctx_t *ctx, const char *args_json,
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

    const char *content = kelp_json_get_string(args, "content");
    if (!content) {
        result->output   = strdup("error: 'content' parameter is required");
        result->is_error = true;
        result->exit_code = -1;
        cJSON_Delete(args);
        return -1;
    }

    KELP_DEBUG("file_write: %s (%zu bytes)", file_path, strlen(content));

    /* Create parent directories */
    char *path_copy = strdup(file_path);
    if (path_copy) {
        char *dir = dirname(path_copy);
        if (dir && strcmp(dir, ".") != 0 && strcmp(dir, "/") != 0) {
            mkdir_p(dir, 0755);
        }
        free(path_copy);
    }

    /* Write the file */
    FILE *fp = fopen(file_path, "w");
    if (!fp) {
        kelp_str_t err = kelp_str_new();
        kelp_str_printf(&err, "error: cannot open file '%s' for writing: %s",
                         file_path, strerror(errno));
        result->output   = err.data ? strdup(err.data) : strdup("error: cannot open file");
        result->is_error = true;
        result->exit_code = 1;
        kelp_str_free(&err);
        cJSON_Delete(args);
        return 0;
    }

    size_t content_len = strlen(content);
    size_t written = fwrite(content, 1, content_len, fp);
    fclose(fp);

    if (written != content_len) {
        kelp_str_t err = kelp_str_new();
        kelp_str_printf(&err, "error: wrote %zu of %zu bytes to '%s'",
                         written, content_len, file_path);
        result->output   = err.data ? strdup(err.data) : strdup("error: incomplete write");
        result->is_error = true;
        result->exit_code = 1;
        kelp_str_free(&err);
    } else {
        kelp_str_t msg = kelp_str_new();
        kelp_str_printf(&msg, "wrote %zu bytes to %s", written, file_path);
        result->output   = msg.data ? strdup(msg.data) : strdup("ok");
        result->is_error = false;
        result->exit_code = 0;
        kelp_str_free(&msg);
    }

    cJSON_Delete(args);
    return 0;
}

/* ---- Registration ------------------------------------------------------- */

const kelp_tool_def_t kelp_file_write_tool_def = {
    .name                 = FILE_WRITE_NAME,
    .description          = FILE_WRITE_DESCRIPTION,
    .params_json          = FILE_WRITE_PARAMS,
    .exec                 = file_write_exec,
    .requires_sandbox     = false,
    .requires_confirmation = true
};
