/*
 * kelp-linux :: libkelp-config
 * config.c - Configuration loading, environment merging, and validation
 *
 * Supports YAML (via libyaml) and JSON (via cJSON) config files.
 * Performs ${ENV_VAR} and ${ENV_VAR:-default} substitution on all strings.
 * Supports profile overlays: profiles/<name>.yaml merged on top of base.
 *
 * SPDX-License-Identifier: MIT
 */

#include "kelp/config.h"
#include "kelp/paths.h"
#include "kelp/schema.h"

#include <cjson/cJSON.h>
#include <yaml.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

/* ======================================================================== */
/* Internal helpers                                                         */
/* ======================================================================== */

/**
 * Safe strdup that handles NULL and returns NULL instead of crashing.
 */
static char *
safe_strdup(const char *s)
{
    return s ? strdup(s) : NULL;
}

/**
 * Replace heap string: free old, assign new copy.
 */
static void
set_str(char **dst, const char *val)
{
    free(*dst);
    *dst = safe_strdup(val);
}

/**
 * Apply environment variable substitution to a string.
 *
 * Recognised patterns:
 *   ${VAR}           -> value of VAR  (empty string if unset)
 *   ${VAR:-default}  -> value of VAR, or "default" if unset/empty
 *
 * Returns a malloc'd string.  Caller must free().
 */
static char *
env_subst(const char *input)
{
    /* Delegate to the fully-featured paths_expand(). */
    return kelp_paths_expand(input);
}

/* ======================================================================== */
/* Default values                                                           */
/* ======================================================================== */

static void
apply_defaults(kelp_config_t *cfg)
{
    if (!cfg->config_dir)
        cfg->config_dir = kelp_paths_config_dir();
    if (!cfg->data_dir)
        cfg->data_dir = kelp_paths_data_dir();
    if (!cfg->runtime_dir)
        cfg->runtime_dir = kelp_paths_runtime_dir();
    if (!cfg->profile)
        cfg->profile = strdup("default");

    /* gateway */
    if (!cfg->gateway.host)
        cfg->gateway.host = strdup("127.0.0.1");
    if (cfg->gateway.port == 0)
        cfg->gateway.port = 8080;
    if (!cfg->gateway.socket_path)
        cfg->gateway.socket_path = kelp_paths_socket();

    /* model */
    if (!cfg->model.default_provider)
        cfg->model.default_provider = strdup("anthropic");
    if (!cfg->model.default_model)
        cfg->model.default_model = strdup("claude-sonnet-4-20250514");
    if (cfg->model.max_tokens == 0)
        cfg->model.max_tokens = 4096;
    if (cfg->model.temperature == 0.0f)
        cfg->model.temperature = 0.7f;

    /* security */
    /* sandbox_enabled defaults to true; we detect "never set" via a
       separate flag (0 is a valid port), but for booleans we rely on
       the struct being zeroed and consider false as default. We choose
       to default to enabled for security. */
    cfg->security.sandbox_enabled = true;
    if (cfg->security.sandbox_memory_mb == 0)
        cfg->security.sandbox_memory_mb = 512;
    if (cfg->security.sandbox_cpu_cores == 0)
        cfg->security.sandbox_cpu_cores = 2;
    if (cfg->security.sandbox_max_pids == 0)
        cfg->security.sandbox_max_pids = 64;

    /* logging */
    if (cfg->logging.level == 0)
        cfg->logging.level = KELP_LOG_INFO;
}

/* ======================================================================== */
/* YAML parser  (libyaml -> cJSON)                                          */
/* ======================================================================== */

/**
 * Recursively parse a YAML document into a cJSON tree.
 *
 * This is a simple recursive-descent parser that walks yaml_document_t nodes.
 */
static cJSON *
yaml_node_to_cjson(yaml_document_t *doc, yaml_node_t *node)
{
    if (!node)
        return cJSON_CreateNull();

    switch (node->type) {
    case YAML_SCALAR_NODE: {
        const char *val = (const char *)node->data.scalar.value;
        size_t len = node->data.scalar.length;

        /* Try to detect booleans */
        if ((len == 4 && strcasecmp(val, "true") == 0) ||
            (len == 3 && strcasecmp(val, "yes") == 0))
            return cJSON_CreateTrue();
        if ((len == 5 && strcasecmp(val, "false") == 0) ||
            (len == 2 && strcasecmp(val, "no") == 0))
            return cJSON_CreateFalse();

        /* null */
        if ((len == 4 && strcasecmp(val, "null") == 0) ||
            (len == 1 && val[0] == '~'))
            return cJSON_CreateNull();

        /* Try integer / float */
        char *endp = NULL;
        long lv = strtol(val, &endp, 10);
        if (endp && *endp == '\0' && endp != val)
            return cJSON_CreateNumber((double)lv);

        endp = NULL;
        double dv = strtod(val, &endp);
        if (endp && *endp == '\0' && endp != val)
            return cJSON_CreateNumber(dv);

        /* Fall through to string */
        return cJSON_CreateString(val);
    }

    case YAML_SEQUENCE_NODE: {
        cJSON *arr = cJSON_CreateArray();
        for (yaml_node_item_t *it = node->data.sequence.items.start;
             it < node->data.sequence.items.top; it++) {
            yaml_node_t *child = yaml_document_get_node(doc, *it);
            cJSON_AddItemToArray(arr, yaml_node_to_cjson(doc, child));
        }
        return arr;
    }

    case YAML_MAPPING_NODE: {
        cJSON *obj = cJSON_CreateObject();
        for (yaml_node_pair_t *pair = node->data.mapping.pairs.start;
             pair < node->data.mapping.pairs.top; pair++) {
            yaml_node_t *key_node = yaml_document_get_node(doc, pair->key);
            yaml_node_t *val_node = yaml_document_get_node(doc, pair->value);
            if (key_node && key_node->type == YAML_SCALAR_NODE) {
                const char *key = (const char *)key_node->data.scalar.value;
                cJSON_AddItemToObject(obj, key, yaml_node_to_cjson(doc, val_node));
            }
        }
        return obj;
    }

    default:
        return cJSON_CreateNull();
    }
}

/**
 * Parse a YAML string into a cJSON tree.
 * Returns NULL on parse error.
 */
static cJSON *
parse_yaml(const char *text, size_t len)
{
    yaml_parser_t parser;
    yaml_document_t document;
    cJSON *result = NULL;

    if (!yaml_parser_initialize(&parser))
        return NULL;

    yaml_parser_set_input_string(&parser, (const unsigned char *)text, len);

    if (!yaml_parser_load(&parser, &document)) {
        yaml_parser_delete(&parser);
        return NULL;
    }

    yaml_node_t *root = yaml_document_get_root_node(&document);
    if (root)
        result = yaml_node_to_cjson(&document, root);

    yaml_document_delete(&document);
    yaml_parser_delete(&parser);
    return result;
}

/* ======================================================================== */
/* cJSON -> kelp_config_t mapping                                          */
/* ======================================================================== */

/**
 * Get a string from a cJSON object, applying env substitution.
 * Returns a malloc'd string or NULL.
 */
static char *
json_get_string_subst(const cJSON *obj, const char *key)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsString(item))
        return NULL;
    return env_subst(item->valuestring);
}

/**
 * Get an int from a cJSON object.
 * Returns the value, or `def` if missing / wrong type.
 */
static int
json_get_int(const cJSON *obj, const char *key, int def)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsNumber(item))
        return def;
    return item->valueint;
}

/**
 * Get a float from a cJSON object.
 */
static float
json_get_float(const cJSON *obj, const char *key, float def)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsNumber(item))
        return def;
    return (float)item->valuedouble;
}

/**
 * Get a bool from a cJSON object.
 */
static bool
json_get_bool(const cJSON *obj, const char *key, bool def)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item)
        return def;
    if (cJSON_IsTrue(item))
        return true;
    if (cJSON_IsFalse(item))
        return false;
    return def;
}

/**
 * Populate a kelp_config_t from a cJSON object tree.
 * Only sets fields that are present in the JSON; does NOT reset unset fields.
 */
static void
populate_from_json(kelp_config_t *cfg, const cJSON *root)
{
    if (!root || !cJSON_IsObject(root))
        return;

    /* Top-level strings */
    {
        char *s;
        if ((s = json_get_string_subst(root, "config_dir")))  { free(cfg->config_dir);  cfg->config_dir  = s; }
        if ((s = json_get_string_subst(root, "data_dir")))    { free(cfg->data_dir);    cfg->data_dir    = s; }
        if ((s = json_get_string_subst(root, "runtime_dir"))) { free(cfg->runtime_dir); cfg->runtime_dir = s; }
        if ((s = json_get_string_subst(root, "profile")))     { free(cfg->profile);     cfg->profile     = s; }
    }

    /* gateway section */
    const cJSON *gw = cJSON_GetObjectItemCaseSensitive(root, "gateway");
    if (gw && cJSON_IsObject(gw)) {
        char *s;
        if ((s = json_get_string_subst(gw, "host")))        { free(cfg->gateway.host);        cfg->gateway.host        = s; }
        if ((s = json_get_string_subst(gw, "socket_path"))) { free(cfg->gateway.socket_path); cfg->gateway.socket_path = s; }
        if ((s = json_get_string_subst(gw, "tls_cert")))    { free(cfg->gateway.tls_cert);    cfg->gateway.tls_cert    = s; }
        if ((s = json_get_string_subst(gw, "tls_key")))     { free(cfg->gateway.tls_key);     cfg->gateway.tls_key     = s; }

        int port = json_get_int(gw, "port", 0);
        if (port > 0) cfg->gateway.port = port;

        /* Only override tls_enabled if explicitly set */
        const cJSON *tls_item = cJSON_GetObjectItemCaseSensitive(gw, "tls_enabled");
        if (tls_item && cJSON_IsBool(tls_item))
            cfg->gateway.tls_enabled = cJSON_IsTrue(tls_item);
    }

    /* model section */
    const cJSON *mdl = cJSON_GetObjectItemCaseSensitive(root, "model");
    if (mdl && cJSON_IsObject(mdl)) {
        char *s;
        if ((s = json_get_string_subst(mdl, "default_provider"))) { free(cfg->model.default_provider); cfg->model.default_provider = s; }
        if ((s = json_get_string_subst(mdl, "default_model")))    { free(cfg->model.default_model);    cfg->model.default_model    = s; }
        if ((s = json_get_string_subst(mdl, "api_key")))          { free(cfg->model.api_key);          cfg->model.api_key          = s; }

        int mt = json_get_int(mdl, "max_tokens", 0);
        if (mt > 0) cfg->model.max_tokens = mt;

        float temp = json_get_float(mdl, "temperature", -1.0f);
        if (temp >= 0.0f) cfg->model.temperature = temp;
    }

    /* security section */
    const cJSON *sec = cJSON_GetObjectItemCaseSensitive(root, "security");
    if (sec && cJSON_IsObject(sec)) {
        const cJSON *sb = cJSON_GetObjectItemCaseSensitive(sec, "sandbox_enabled");
        if (sb && cJSON_IsBool(sb))
            cfg->security.sandbox_enabled = cJSON_IsTrue(sb);

        int v;
        v = json_get_int(sec, "sandbox_memory_mb", 0);
        if (v > 0) cfg->security.sandbox_memory_mb = v;
        v = json_get_int(sec, "sandbox_cpu_cores", 0);
        if (v > 0) cfg->security.sandbox_cpu_cores = v;
        v = json_get_int(sec, "sandbox_max_pids", 0);
        if (v > 0) cfg->security.sandbox_max_pids = v;

        /* allowed_paths array */
        const cJSON *ap = cJSON_GetObjectItemCaseSensitive(sec, "allowed_paths");
        if (ap && cJSON_IsArray(ap)) {
            int count = cJSON_GetArraySize(ap);
            /* Free previous */
            for (int i = 0; i < cfg->security.allowed_paths_count; i++)
                free(cfg->security.allowed_paths[i]);
            free(cfg->security.allowed_paths);

            cfg->security.allowed_paths = calloc((size_t)count, sizeof(char *));
            cfg->security.allowed_paths_count = 0;
            if (cfg->security.allowed_paths) {
                for (int i = 0; i < count; i++) {
                    const cJSON *elem = cJSON_GetArrayItem(ap, i);
                    if (cJSON_IsString(elem)) {
                        char *expanded = env_subst(elem->valuestring);
                        cfg->security.allowed_paths[cfg->security.allowed_paths_count++] =
                            expanded ? expanded : strdup(elem->valuestring);
                    }
                }
            }
        }
    }

    /* logging section */
    const cJSON *log_sec = cJSON_GetObjectItemCaseSensitive(root, "logging");
    if (log_sec && cJSON_IsObject(log_sec)) {
        /* level can be an int or a string name */
        const cJSON *lvl = cJSON_GetObjectItemCaseSensitive(log_sec, "level");
        if (lvl) {
            if (cJSON_IsNumber(lvl)) {
                cfg->logging.level = lvl->valueint;
            } else if (cJSON_IsString(lvl)) {
                const char *s = lvl->valuestring;
                if      (strcasecmp(s, "emerg")   == 0) cfg->logging.level = KELP_LOG_EMERG;
                else if (strcasecmp(s, "alert")   == 0) cfg->logging.level = KELP_LOG_ALERT;
                else if (strcasecmp(s, "crit")    == 0) cfg->logging.level = KELP_LOG_CRIT;
                else if (strcasecmp(s, "err")     == 0 ||
                         strcasecmp(s, "error")   == 0) cfg->logging.level = KELP_LOG_ERR;
                else if (strcasecmp(s, "warning") == 0 ||
                         strcasecmp(s, "warn")    == 0) cfg->logging.level = KELP_LOG_WARNING;
                else if (strcasecmp(s, "notice")  == 0) cfg->logging.level = KELP_LOG_NOTICE;
                else if (strcasecmp(s, "info")    == 0) cfg->logging.level = KELP_LOG_INFO;
                else if (strcasecmp(s, "debug")   == 0) cfg->logging.level = KELP_LOG_DEBUG;
            }
        }

        char *lf = json_get_string_subst(log_sec, "file");
        if (lf) { free(cfg->logging.file); cfg->logging.file = lf; }
    }
}

/* ======================================================================== */
/* File I/O                                                                 */
/* ======================================================================== */

/**
 * Read a file into a malloc'd buffer.  Sets *out_len.
 * Returns NULL on failure.
 */
static char *
read_file(const char *path, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return NULL;

    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return NULL; }
    rewind(fp);

    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return NULL; }

    size_t rd = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);

    buf[rd] = '\0';
    if (out_len)
        *out_len = rd;
    return buf;
}

/**
 * Check if a path ends with a given suffix (case-insensitive).
 */
static bool
has_extension(const char *path, const char *ext)
{
    size_t plen = strlen(path);
    size_t elen = strlen(ext);
    if (plen < elen)
        return false;
    return strcasecmp(path + plen - elen, ext) == 0;
}

/**
 * Parse file contents into a cJSON tree, auto-detecting YAML vs JSON.
 */
static cJSON *
parse_file(const char *path, const char *text, size_t len)
{
    if (has_extension(path, ".json")) {
        return cJSON_ParseWithLength(text, len);
    }
    /* Default: YAML (.yaml, .yml, or anything else) */
    return parse_yaml(text, len);
}

/* ======================================================================== */
/* Profile overlay                                                          */
/* ======================================================================== */

/**
 * If a profile is set and != "default", look for a profile overlay file
 * in the same directory as the base config file.
 *
 * E.g. if base is /etc/kelp/kelp.yaml and profile is "dev",
 * look for /etc/kelp/profiles/dev.yaml.
 */
static void
load_profile_overlay(kelp_config_t *cfg, const char *base_path)
{
    if (!cfg->profile || strcmp(cfg->profile, "default") == 0)
        return;

    /* Extract directory from base_path */
    const char *last_sep = strrchr(base_path, '/');
    size_t dir_len = last_sep ? (size_t)(last_sep - base_path) : 0;

    char overlay_path[4096];
    if (dir_len > 0)
        snprintf(overlay_path, sizeof(overlay_path),
                 "%.*s/profiles/%s.yaml", (int)dir_len, base_path, cfg->profile);
    else
        snprintf(overlay_path, sizeof(overlay_path),
                 "profiles/%s.yaml", cfg->profile);

    size_t len = 0;
    char *text = read_file(overlay_path, &len);
    if (!text)
        return; /* profile file missing is not an error */

    cJSON *root = parse_file(overlay_path, text, len);
    free(text);

    if (root) {
        populate_from_json(cfg, root);
        cJSON_Delete(root);
    }
}

/* ======================================================================== */
/* Public API                                                                */
/* ======================================================================== */

int
kelp_config_load(const char *path, kelp_config_t *cfg)
{
    if (!path || !cfg)
        return -1;

    memset(cfg, 0, sizeof(*cfg));

    size_t len = 0;
    char *text = read_file(path, &len);
    if (!text)
        return -1;

    cJSON *root = parse_file(path, text, len);
    free(text);

    if (!root)
        return -1;

    populate_from_json(cfg, root);
    cJSON_Delete(root);

    /* Profile overlay */
    load_profile_overlay(cfg, path);

    /* Fill in anything the file didn't set */
    apply_defaults(cfg);

    return 0;
}

int
kelp_config_load_default(kelp_config_t *cfg)
{
    if (!cfg)
        return -1;

    memset(cfg, 0, sizeof(*cfg));

    /* Build candidate paths */
    const char *candidates[3] = { NULL, NULL, NULL };
    char path_env[4096]  = {0};
    char path_home[4096] = {0};

    /* 1. $KELP_CONFIG_DIR/kelp.yaml */
    const char *env_dir = getenv("KELP_CONFIG_DIR");
    if (env_dir && env_dir[0]) {
        snprintf(path_env, sizeof(path_env), "%s/kelp.yaml", env_dir);
        candidates[0] = path_env;
    }

    /* 2. ~/.config/kelp/kelp.yaml  (or $XDG_CONFIG_HOME/kelp/kelp.yaml) */
    {
        char *cdir = kelp_paths_config_dir();
        if (cdir) {
            snprintf(path_home, sizeof(path_home), "%s/kelp.yaml", cdir);
            candidates[1] = path_home;
            free(cdir);
        }
    }

    /* 3. /etc/kelp/kelp.yaml */
    candidates[2] = "/etc/kelp/kelp.yaml";

    /* Try each candidate */
    for (int i = 0; i < 3; i++) {
        if (!candidates[i])
            continue;
        if (access(candidates[i], R_OK) == 0) {
            int rc = kelp_config_load(candidates[i], cfg);
            /* config_load already applied defaults */
            return rc;
        }
    }

    /* No file found -- apply defaults only */
    apply_defaults(cfg);
    return 0;
}

void
kelp_config_free(kelp_config_t *cfg)
{
    if (!cfg)
        return;

    free(cfg->config_dir);
    free(cfg->data_dir);
    free(cfg->runtime_dir);
    free(cfg->profile);

    free(cfg->gateway.host);
    free(cfg->gateway.socket_path);
    free(cfg->gateway.tls_cert);
    free(cfg->gateway.tls_key);

    free(cfg->model.default_provider);
    free(cfg->model.default_model);
    free(cfg->model.api_key);
    free(cfg->model.system_prompt);

    for (int i = 0; i < cfg->security.allowed_paths_count; i++)
        free(cfg->security.allowed_paths[i]);
    free(cfg->security.allowed_paths);

    free(cfg->logging.file);

    memset(cfg, 0, sizeof(*cfg));
}

/* ======================================================================== */
/* Keyed accessors                                                          */
/* ======================================================================== */

const char *
kelp_config_get_string(const kelp_config_t *cfg, const char *key)
{
    if (!cfg || !key)
        return NULL;

    /* Top-level */
    if (strcmp(key, "config_dir")  == 0) return cfg->config_dir;
    if (strcmp(key, "data_dir")    == 0) return cfg->data_dir;
    if (strcmp(key, "runtime_dir") == 0) return cfg->runtime_dir;
    if (strcmp(key, "profile")     == 0) return cfg->profile;

    /* gateway.* */
    if (strcmp(key, "gateway.host")        == 0) return cfg->gateway.host;
    if (strcmp(key, "gateway.socket_path") == 0) return cfg->gateway.socket_path;
    if (strcmp(key, "gateway.tls_cert")    == 0) return cfg->gateway.tls_cert;
    if (strcmp(key, "gateway.tls_key")     == 0) return cfg->gateway.tls_key;

    /* model.* */
    if (strcmp(key, "model.default_provider") == 0) return cfg->model.default_provider;
    if (strcmp(key, "model.default_model")    == 0) return cfg->model.default_model;
    if (strcmp(key, "model.api_key")          == 0) return cfg->model.api_key;

    /* logging.* */
    if (strcmp(key, "logging.file") == 0) return cfg->logging.file;

    return NULL;
}

int
kelp_config_get_int(const kelp_config_t *cfg, const char *key, int def)
{
    if (!cfg || !key)
        return def;

    if (strcmp(key, "gateway.port")              == 0) return cfg->gateway.port;
    if (strcmp(key, "model.max_tokens")          == 0) return cfg->model.max_tokens;
    if (strcmp(key, "security.sandbox_memory_mb") == 0) return cfg->security.sandbox_memory_mb;
    if (strcmp(key, "security.sandbox_cpu_cores") == 0) return cfg->security.sandbox_cpu_cores;
    if (strcmp(key, "security.sandbox_max_pids")  == 0) return cfg->security.sandbox_max_pids;
    if (strcmp(key, "logging.level")              == 0) return cfg->logging.level;

    return def;
}

bool
kelp_config_get_bool(const kelp_config_t *cfg, const char *key, bool def)
{
    if (!cfg || !key)
        return def;

    if (strcmp(key, "gateway.tls_enabled")      == 0) return cfg->gateway.tls_enabled;
    if (strcmp(key, "security.sandbox_enabled")  == 0) return cfg->security.sandbox_enabled;

    return def;
}

/* ======================================================================== */
/* Environment merging                                                      */
/* ======================================================================== */

/**
 * Parse a log-level string (name or number) into an integer.
 */
static int
parse_log_level(const char *s)
{
    if (!s)
        return -1;

    /* Try numeric first */
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (end && *end == '\0' && end != s)
        return (int)v;

    if (strcasecmp(s, "emerg")   == 0) return KELP_LOG_EMERG;
    if (strcasecmp(s, "alert")   == 0) return KELP_LOG_ALERT;
    if (strcasecmp(s, "crit")    == 0) return KELP_LOG_CRIT;
    if (strcasecmp(s, "err")     == 0 ||
        strcasecmp(s, "error")   == 0) return KELP_LOG_ERR;
    if (strcasecmp(s, "warning") == 0 ||
        strcasecmp(s, "warn")    == 0) return KELP_LOG_WARNING;
    if (strcasecmp(s, "notice")  == 0) return KELP_LOG_NOTICE;
    if (strcasecmp(s, "info")    == 0) return KELP_LOG_INFO;
    if (strcasecmp(s, "debug")   == 0) return KELP_LOG_DEBUG;

    return -1;
}

/**
 * Return true if a string looks truthy ("1", "true", "yes", case-insensitive).
 */
static bool
parse_bool_env(const char *s)
{
    if (!s)
        return false;
    return (strcmp(s, "1") == 0 ||
            strcasecmp(s, "true") == 0 ||
            strcasecmp(s, "yes") == 0);
}

int
kelp_config_merge_env(kelp_config_t *cfg)
{
    if (!cfg)
        return 0;

    const char *v;

    if ((v = getenv("KELP_HOST")))         set_str(&cfg->gateway.host, v);
    if ((v = getenv("KELP_SOCKET")))       set_str(&cfg->gateway.socket_path, v);
    if ((v = getenv("KELP_TLS_CERT")))     set_str(&cfg->gateway.tls_cert, v);
    if ((v = getenv("KELP_TLS_KEY")))      set_str(&cfg->gateway.tls_key, v);
    if ((v = getenv("KELP_PROVIDER")))     set_str(&cfg->model.default_provider, v);
    if ((v = getenv("KELP_MODEL")))        set_str(&cfg->model.default_model, v);
    if ((v = getenv("KELP_API_KEY")))      set_str(&cfg->model.api_key, v);
    if ((v = getenv("KELP_SYSTEM_PROMPT"))) set_str(&cfg->model.system_prompt, v);
    if ((v = getenv("KELP_LOG_FILE")))     set_str(&cfg->logging.file, v);
    if ((v = getenv("KELP_PROFILE")))      set_str(&cfg->profile, v);

    if ((v = getenv("KELP_PORT"))) {
        int p = atoi(v);
        if (p > 0 && p <= 65535)
            cfg->gateway.port = p;
    }

    if ((v = getenv("KELP_MAX_TOKENS"))) {
        int mt = atoi(v);
        if (mt > 0)
            cfg->model.max_tokens = mt;
    }

    if ((v = getenv("KELP_TEMPERATURE"))) {
        float t = (float)atof(v);
        if (t >= 0.0f)
            cfg->model.temperature = t;
    }

    if ((v = getenv("KELP_SANDBOX")))
        cfg->security.sandbox_enabled = parse_bool_env(v);

    if ((v = getenv("KELP_LOG_LEVEL"))) {
        int lvl = parse_log_level(v);
        if (lvl >= 0)
            cfg->logging.level = lvl;
    }

    /* TLS enabled if both cert and key are set */
    if (getenv("KELP_TLS_CERT") && getenv("KELP_TLS_KEY"))
        cfg->gateway.tls_enabled = true;

    return 0;
}

/* ======================================================================== */
/* Validation                                                               */
/* ======================================================================== */

int
kelp_config_validate(const kelp_config_t *cfg)
{
    if (!cfg)
        return -1;

    /* Port range */
    if (cfg->gateway.port < 1 || cfg->gateway.port > 65535)
        return -1;

    /* If TLS is enabled, cert and key must be set */
    if (cfg->gateway.tls_enabled) {
        if (!cfg->gateway.tls_cert || !cfg->gateway.tls_cert[0])
            return -1;
        if (!cfg->gateway.tls_key || !cfg->gateway.tls_key[0])
            return -1;
    }

    /* max_tokens */
    if (cfg->model.max_tokens < 1)
        return -1;

    /* temperature */
    if (cfg->model.temperature < 0.0f || cfg->model.temperature > 2.0f)
        return -1;

    /* sandbox limits */
    if (cfg->security.sandbox_memory_mb < 1 || cfg->security.sandbox_memory_mb > 65536)
        return -1;
    if (cfg->security.sandbox_cpu_cores < 1 || cfg->security.sandbox_cpu_cores > 256)
        return -1;
    if (cfg->security.sandbox_max_pids < 1 || cfg->security.sandbox_max_pids > 32768)
        return -1;

    /* Log level */
    if (cfg->logging.level < 0 || cfg->logging.level > 7)
        return -1;

    return 0;
}
