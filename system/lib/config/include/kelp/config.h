/*
 * kelp-linux :: libkelp-config
 * config.h - Configuration loading, merging, and validation
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_CONFIG_H
#define KELP_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Log-level constants (same as syslog severity). */
#define KELP_LOG_EMERG   0
#define KELP_LOG_ALERT   1
#define KELP_LOG_CRIT    2
#define KELP_LOG_ERR     3
#define KELP_LOG_WARNING 4
#define KELP_LOG_NOTICE  5
#define KELP_LOG_INFO    6
#define KELP_LOG_DEBUG   7

/**
 * Top-level configuration object.
 *
 * Populated by `kelp_config_load()` or `kelp_config_load_default()`.
 * All string fields are heap-allocated and freed by `kelp_config_free()`.
 */
typedef struct kelp_config {
    char *config_dir;      /* ~/.config/kelp                          */
    char *data_dir;        /* ~/.local/share/kelp                     */
    char *runtime_dir;     /* /run/kelp  or  $XDG_RUNTIME_DIR/kelp   */
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
        char  *system_prompt;      /* default system prompt for all chats */
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
        int   level;   /* KELP_LOG_* constant */
        char *file;
    } logging;
} kelp_config_t;

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
int kelp_config_load(const char *path, kelp_config_t *cfg);

/**
 * Load configuration from the first file found in the standard search order:
 *
 *   1.  $KELP_CONFIG_DIR/kelp.yaml
 *   2.  ~/.config/kelp/kelp.yaml
 *   3.  /etc/kelp/kelp.yaml
 *
 * If no file is found, sensible defaults are applied.
 *
 * @param cfg  Output struct.
 * @return 0 on success (even with defaults only), -1 on parse error.
 */
int kelp_config_load_default(kelp_config_t *cfg);

/**
 * Free all heap memory owned by @p cfg and zero the struct.
 */
void kelp_config_free(kelp_config_t *cfg);

/**
 * Retrieve a string field by dotted key path (e.g. "gateway.host").
 *
 * @return Pointer into the config struct (do NOT free), or NULL if the key
 *         is not recognised or the field is unset.
 */
const char *kelp_config_get_string(const kelp_config_t *cfg, const char *key);

/**
 * Retrieve an integer field by dotted key path.
 *
 * @return The field value, or @p def if the key is not recognised.
 */
int kelp_config_get_int(const kelp_config_t *cfg, const char *key, int def);

/**
 * Retrieve a boolean field by dotted key path.
 *
 * @return The field value, or @p def if the key is not recognised.
 */
bool kelp_config_get_bool(const kelp_config_t *cfg, const char *key, bool def);

/**
 * Apply overrides from KELP_* environment variables.
 *
 * Mapping (env -> field):
 *   KELP_HOST              -> gateway.host
 *   KELP_PORT              -> gateway.port
 *   KELP_SOCKET            -> gateway.socket_path
 *   KELP_TLS_CERT          -> gateway.tls_cert
 *   KELP_TLS_KEY           -> gateway.tls_key
 *   KELP_PROVIDER          -> model.default_provider
 *   KELP_MODEL             -> model.default_model
 *   KELP_API_KEY           -> model.api_key
 *   KELP_MAX_TOKENS        -> model.max_tokens
 *   KELP_TEMPERATURE       -> model.temperature
 *   KELP_SANDBOX           -> security.sandbox_enabled  ("1"/"true"/"yes")
 *   KELP_LOG_LEVEL         -> logging.level  (integer or name)
 *   KELP_LOG_FILE          -> logging.file
 *   KELP_PROFILE           -> profile
 *
 * @return 0 always (env overrides never fail).
 */
int kelp_config_merge_env(kelp_config_t *cfg);

/**
 * Validate the configuration for internal consistency.
 *
 * Checks required fields, numeric ranges, path existence, etc.
 *
 * @return 0 if valid, -1 if one or more problems are found.
 */
int kelp_config_validate(const kelp_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* KELP_CONFIG_H */
