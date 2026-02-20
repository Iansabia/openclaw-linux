/*
 * clawd-linux :: libclawd-core
 * json.h - Convenience wrappers around cJSON
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_JSON_H
#define CLAWD_JSON_H

#include <stdbool.h>
#include <cjson/cJSON.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Parse a JSON string. Returns a cJSON tree (caller must cJSON_Delete). */
cJSON *clawd_json_parse(const char *text);

/** Read and parse a JSON file. Returns a cJSON tree or NULL on error. */
cJSON *clawd_json_parse_file(const char *path);

/**
 * Retrieve a string field from a JSON object.
 * Returns a pointer into the cJSON tree (do NOT free), or NULL.
 */
const char *clawd_json_get_string(const cJSON *obj, const char *key);

/** Retrieve an integer field, returning `def` if the key is absent/wrong type. */
int clawd_json_get_int(const cJSON *obj, const char *key, int def);

/** Retrieve a boolean field, returning `def` if the key is absent/wrong type. */
bool clawd_json_get_bool(const cJSON *obj, const char *key, bool def);

/** Retrieve an array field. Returns the cJSON node or NULL. */
cJSON *clawd_json_get_array(const cJSON *obj, const char *key);

/** Retrieve a nested object field. Returns the cJSON node or NULL. */
cJSON *clawd_json_get_object(const cJSON *obj, const char *key);

/** Serialize a cJSON tree to a compact string (caller must free). */
char *clawd_json_stringify(const cJSON *obj);

/** Serialize a cJSON tree to a pretty-printed string (caller must free). */
char *clawd_json_stringify_pretty(const cJSON *obj);

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_JSON_H */
