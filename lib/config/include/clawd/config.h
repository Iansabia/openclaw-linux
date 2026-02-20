/*
 * clawd-linux :: libclawd-config
 * config.h - Configuration loading, merging, and validation
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_CONFIG_H
#define CLAWD_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Log-level constants (same as syslog severity). */
#define CLAWD_LOG_EMERG   0
#define CLAWD_LOG_ALERT   1
#define CLAWD_LOG_CRIT    2
#define CLAWD_LOG_ERR     3
#define CLAWD_LOG_WARNING 4
#define CLAWD_LOG_NOTICE  5
#define CLAWD_LOG_INFO    6
#define CLAWD_LOG_DEBUG   7

/**
 * Top-level configuration object.
 *
 * Populated by `clawd_config_load()` or `clawd_config_load_default()`.
 * All string fields are heap-allocated and freed by `clawd_config_free()`.
 */
typedef struct clawd_config {
    char *config_dir;      /* ~/.config/clawd                          */
    char *data_dir;        /* ~/.local/share/clawd                     */
    char *runtime_dir;     /* /run/clawd  or  $XDG_RUNTIME_DIR/clawd   */
    char *profile;         /* active profile name (NULL = "default")   */

    /* ---- Gateway settings ---- */
    struct {
        char *host;
        int   port;
        char *socket_path;   /* Unix domain socket path */
        bool  tls_enabled;
        char *tls_cert;
        char *tls_key;
    } gateway;

    /* ---- Model / provider settings ---- */
    struct {
        char  *default_provider;   /* "anthropic", "openai", ... */
        char  *default_model;
        char  *api_key;
        int    max_tokens;
        float  temperature;
    } model;

    /* ---- Security / sandbox settings ---- */
    struct {
        bool   sandbox_enabled;
        int    sandbox_memory_mb;
        int    sandbox_cpu_cores;
        int    sandbox_max_pids;
        char **allowed_paths;
        int    allowed_paths_count;
    } security;

    /* ---- Logging ---- */
    struct {
        int   level;   /* CLAWD_LOG_* constant */
        char *file;
    } logging;
} clawd_config_t;

/**
 * Load configuration from a specific YAML or JSON file.
 *
 * The file format is detected by extension (.json -> JSON, everything else ->
 * YAML).  Environment variable substitution (${VAR} / ${VAR:-default}) is
 * performed on every string value.
 *
 * @param path  Absolute or relative path to the configuration file.
 * @param cfg   Output struct (zeroed first, then populated).
 * @return 0 on success, -1 on error.
 */
int clawd_config_load(const char *path, clawd_config_t *cfg);

/**
 * Load configuration from the first file found in the standard search order:
 *
 *   1.  $CLAWD_CONFIG_DIR/clawd.yaml
 *   2.  ~/.config/clawd/clawd.yaml
 *   3.  /etc/clawd/clawd.yaml
 *
 * If no file is found, sensible defaults are applied.
 *
 * @param cfg  Output struct.
 * @return 0 on success (even with defaults only), -1 on parse error.
 */
int clawd_config_load_default(clawd_config_t *cfg);

/**
 * Free all heap memory owned by @p cfg and zero the struct.
 */
void clawd_config_free(clawd_config_t *cfg);

/**
 * Retrieve a string field by dotted key path (e.g. "gateway.host").
 *
 * @return Pointer into the config struct (do NOT free), or NULL if the key
 *         is not recognised or the field is unset.
 */
const char *clawd_config_get_string(const clawd_config_t *cfg, const char *key);

/**
 * Retrieve an integer field by dotted key path.
 *
 * @return The field value, or @p def if the key is not recognised.
 */
int clawd_config_get_int(const clawd_config_t *cfg, const char *key, int def);

/**
 * Retrieve a boolean field by dotted key path.
 *
 * @return The field value, or @p def if the key is not recognised.
 */
bool clawd_config_get_bool(const clawd_config_t *cfg, const char *key, bool def);

/**
 * Apply overrides from CLAWD_* environment variables.
 *
 * Mapping (env -> field):
 *   CLAWD_HOST              -> gateway.host
 *   CLAWD_PORT              -> gateway.port
 *   CLAWD_SOCKET            -> gateway.socket_path
 *   CLAWD_TLS_CERT          -> gateway.tls_cert
 *   CLAWD_TLS_KEY           -> gateway.tls_key
 *   CLAWD_PROVIDER          -> model.default_provider
 *   CLAWD_MODEL             -> model.default_model
 *   CLAWD_API_KEY           -> model.api_key
 *   CLAWD_MAX_TOKENS        -> model.max_tokens
 *   CLAWD_TEMPERATURE       -> model.temperature
 *   CLAWD_SANDBOX           -> security.sandbox_enabled  ("1"/"true"/"yes")
 *   CLAWD_LOG_LEVEL         -> logging.level  (integer or name)
 *   CLAWD_LOG_FILE          -> logging.file
 *   CLAWD_PROFILE           -> profile
 *
 * @return 0 always (env overrides never fail).
 */
int clawd_config_merge_env(clawd_config_t *cfg);

/**
 * Validate the configuration for internal consistency.
 *
 * Checks required fields, numeric ranges, path existence, etc.
 *
 * @return 0 if valid, -1 if one or more problems are found.
 */
int clawd_config_validate(const clawd_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_CONFIG_H */
