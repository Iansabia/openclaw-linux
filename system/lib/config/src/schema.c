/*
 * kelp-linux :: libkelp-config
 * schema.c - Schema validation against cJSON objects
 *
 * SPDX-License-Identifier: MIT
 */

#include "kelp/schema.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Internal helpers                                                         */
/* ------------------------------------------------------------------------ */

/**
 * Resolve a dotted key path (e.g. "gateway.port") within a cJSON tree.
 *
 * Returns NULL if the path does not exist.
 */
static const cJSON *
resolve_path(const cJSON *root, const char *dotted)
{
    if (!root || !dotted)
        return NULL;

    /* Work on a mutable copy of the key. */
    char tmp[256];
    size_t len = strlen(dotted);
    if (len >= sizeof(tmp))
        return NULL;
    memcpy(tmp, dotted, len + 1);

    const cJSON *cur = root;
    char *save = NULL;
    char *tok  = strtok_r(tmp, ".", &save);
    while (tok) {
        cur = cJSON_GetObjectItemCaseSensitive(cur, tok);
        if (!cur)
            return NULL;
        tok = strtok_r(NULL, ".", &save);
    }
    return cur;
}

/**
 * Check whether a cJSON item matches the expected schema type.
 */
static int
check_type(const cJSON *item, kelp_schema_type_t type)
{
    switch (type) {
    case SCHEMA_STRING:
        return cJSON_IsString(item) ? 0 : -1;
    case SCHEMA_INT:
        return cJSON_IsNumber(item) ? 0 : -1;
    case SCHEMA_FLOAT:
        return cJSON_IsNumber(item) ? 0 : -1;
    case SCHEMA_BOOL:
        return cJSON_IsBool(item) ? 0 : -1;
    case SCHEMA_ARRAY:
        return cJSON_IsArray(item) ? 0 : -1;
    case SCHEMA_OBJECT:
        return cJSON_IsObject(item) ? 0 : -1;
    }
    return -1;
}

/**
 * Return a human-readable name for a schema type.
 */
static const char *
type_name(kelp_schema_type_t type)
{
    switch (type) {
    case SCHEMA_STRING: return "string";
    case SCHEMA_INT:    return "int";
    case SCHEMA_FLOAT:  return "float";
    case SCHEMA_BOOL:   return "bool";
    case SCHEMA_ARRAY:  return "array";
    case SCHEMA_OBJECT: return "object";
    }
    return "unknown";
}

/* ------------------------------------------------------------------------ */
/* Public API                                                                */
/* ------------------------------------------------------------------------ */

int
kelp_schema_validate(const kelp_schema_t *schema,
                       const cJSON          *data,
                       char                 *err_buf,
                       size_t                err_len)
{
    if (!schema || !data) {
        if (err_buf && err_len > 0)
            snprintf(err_buf, err_len, "schema or data is NULL");
        return -1;
    }

    for (int i = 0; i < schema->field_count; i++) {
        const kelp_schema_field_t *f = &schema->fields[i];
        const cJSON *item = resolve_path(data, f->name);

        /* --- required check --- */
        if (!item || cJSON_IsNull(item)) {
            if (f->required) {
                if (err_buf && err_len > 0)
                    snprintf(err_buf, err_len,
                             "missing required field \"%s\"", f->name);
                return -1;
            }
            continue; /* optional and absent -- ok */
        }

        /* --- type check --- */
        if (check_type(item, f->type) != 0) {
            if (err_buf && err_len > 0)
                snprintf(err_buf, err_len,
                         "field \"%s\": expected type %s",
                         f->name, type_name(f->type));
            return -1;
        }

        /* --- range / length check (only for numbers and strings) --- */
        if (f->type == SCHEMA_INT || f->type == SCHEMA_FLOAT) {
            double v = item->valuedouble;
            if (f->min != 0 || f->max != 0) {
                if (f->min != 0 && v < (double)f->min) {
                    if (err_buf && err_len > 0)
                        snprintf(err_buf, err_len,
                                 "field \"%s\": value %g < min %d",
                                 f->name, v, f->min);
                    return -1;
                }
                if (f->max != 0 && v > (double)f->max) {
                    if (err_buf && err_len > 0)
                        snprintf(err_buf, err_len,
                                 "field \"%s\": value %g > max %d",
                                 f->name, v, f->max);
                    return -1;
                }
            }
        } else if (f->type == SCHEMA_STRING && cJSON_IsString(item)) {
            size_t slen = strlen(item->valuestring);
            if (f->min != 0 && (int)slen < f->min) {
                if (err_buf && err_len > 0)
                    snprintf(err_buf, err_len,
                             "field \"%s\": string length %zu < min %d",
                             f->name, slen, f->min);
                return -1;
            }
            if (f->max != 0 && (int)slen > f->max) {
                if (err_buf && err_len > 0)
                    snprintf(err_buf, err_len,
                             "field \"%s\": string length %zu > max %d",
                             f->name, slen, f->max);
                return -1;
            }
        } else if (f->type == SCHEMA_ARRAY && cJSON_IsArray(item)) {
            int count = cJSON_GetArraySize(item);
            if (f->min != 0 && count < f->min) {
                if (err_buf && err_len > 0)
                    snprintf(err_buf, err_len,
                             "field \"%s\": array length %d < min %d",
                             f->name, count, f->min);
                return -1;
            }
            if (f->max != 0 && count > f->max) {
                if (err_buf && err_len > 0)
                    snprintf(err_buf, err_len,
                             "field \"%s\": array length %d > max %d",
                             f->name, count, f->max);
                return -1;
            }
        }
    }

    if (err_buf && err_len > 0)
        err_buf[0] = '\0';
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Built-in config schema                                                    */
/* ------------------------------------------------------------------------ */

static const kelp_schema_field_t config_fields[] = {
    /* name                          type            req    default       min  max  */
    { "profile",                     SCHEMA_STRING,  false, "default",     0,  128 },

    /* gateway */
    { "gateway",                     SCHEMA_OBJECT,  false, NULL,          0,    0 },
    { "gateway.host",                SCHEMA_STRING,  false, "127.0.0.1",   1,  255 },
    { "gateway.port",                SCHEMA_INT,     false, "8080",        1, 65535},
    { "gateway.socket_path",         SCHEMA_STRING,  false, NULL,          0, 4096 },
    { "gateway.tls_enabled",         SCHEMA_BOOL,    false, "false",       0,    0 },
    { "gateway.tls_cert",            SCHEMA_STRING,  false, NULL,          0, 4096 },
    { "gateway.tls_key",             SCHEMA_STRING,  false, NULL,          0, 4096 },

    /* model */
    { "model",                       SCHEMA_OBJECT,  false, NULL,          0,    0 },
    { "model.default_provider",      SCHEMA_STRING,  false, "anthropic",   1,   64 },
    { "model.default_model",         SCHEMA_STRING,  false, NULL,          0,  128 },
    { "model.api_key",               SCHEMA_STRING,  false, NULL,          0, 1024 },
    { "model.max_tokens",            SCHEMA_INT,     false, "4096",        1, 1000000},
    { "model.temperature",           SCHEMA_FLOAT,   false, "0.7",         0,    2 },

    /* security */
    { "security",                    SCHEMA_OBJECT,  false, NULL,          0,    0 },
    { "security.sandbox_enabled",    SCHEMA_BOOL,    false, "true",        0,    0 },
    { "security.sandbox_memory_mb",  SCHEMA_INT,     false, "512",         1, 65536},
    { "security.sandbox_cpu_cores",  SCHEMA_INT,     false, "2",           1,  256 },
    { "security.sandbox_max_pids",   SCHEMA_INT,     false, "64",          1, 32768},
    { "security.allowed_paths",      SCHEMA_ARRAY,   false, NULL,          0,    0 },

    /* logging */
    { "logging",                     SCHEMA_OBJECT,  false, NULL,          0,    0 },
    { "logging.level",               SCHEMA_INT,     false, "6",           0,    7 },
    { "logging.file",                SCHEMA_STRING,  false, NULL,          0, 4096 },
};

static const kelp_schema_t config_schema = {
    .fields      = config_fields,
    .field_count = (int)(sizeof(config_fields) / sizeof(config_fields[0])),
};

const kelp_schema_t *
kelp_schema_config(void)
{
    return &config_schema;
}
