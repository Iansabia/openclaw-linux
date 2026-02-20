/*
 * clawd-linux :: libclawd-config
 * schema.h - Schema-driven validation (replaces Zod/JSON-Schema in C)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_SCHEMA_H
#define CLAWD_SCHEMA_H

#include <stdbool.h>
#include <stddef.h>

/* Forward-declare cJSON so users do not need to include cJSON.h directly. */
struct cJSON;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Supported schema value types.
 */
typedef enum {
    SCHEMA_STRING  = 0,
    SCHEMA_INT     = 1,
    SCHEMA_FLOAT   = 2,
    SCHEMA_BOOL    = 3,
    SCHEMA_ARRAY   = 4,
    SCHEMA_OBJECT  = 5
} clawd_schema_type_t;

/**
 * Descriptor for a single field in a schema.
 */
typedef struct {
    const char          *name;           /* dotted field name (e.g. "gateway.port") */
    clawd_schema_type_t  type;
    bool                 required;
    const char          *default_value;  /* textual representation, or NULL       */
    int                  min;            /* minimum value / length (inclusive)     */
    int                  max;            /* maximum value / length (0 = no limit) */
} clawd_schema_field_t;

/**
 * A schema is simply an array of field descriptors.
 */
typedef struct {
    const clawd_schema_field_t *fields;
    int                         field_count;
} clawd_schema_t;

/**
 * Validate a cJSON object tree against @p schema.
 *
 * On success returns 0.  On failure returns -1 and writes a human-readable
 * error description into @p err_buf (up to @p err_len - 1 characters).
 */
int clawd_schema_validate(const clawd_schema_t *schema,
                           const struct cJSON   *data,
                           char                 *err_buf,
                           size_t                err_len);

/**
 * Return the built-in schema that describes the top-level clawd configuration.
 *
 * The returned pointer is to a static object and must NOT be freed.
 */
const clawd_schema_t *clawd_schema_config(void);

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_SCHEMA_H */
