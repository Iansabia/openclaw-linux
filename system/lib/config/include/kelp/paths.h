/*
 * kelp-linux :: libkelp-config
 * paths.h - XDG-compliant path resolution and directory creation
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_PATHS_H
#define KELP_PATHS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Return the configuration directory.
 *
 * Resolution order:
 *   1. $KELP_CONFIG_DIR
 *   2. $XDG_CONFIG_HOME/kelp
 *   3. ~/.config/kelp
 *
 * @return Newly allocated string.  Caller must free().
 */
char *kelp_paths_config_dir(void);

/**
 * Return the data directory.
 *
 * Resolution order:
 *   1. $KELP_DATA_DIR
 *   2. $XDG_DATA_HOME/kelp
 *   3. ~/.local/share/kelp
 *
 * @return Newly allocated string.  Caller must free().
 */
char *kelp_paths_data_dir(void);

/**
 * Return the runtime directory.
 *
 * Resolution order:
 *   1. $KELP_RUNTIME_DIR
 *   2. $XDG_RUNTIME_DIR/kelp
 *   3. /run/kelp  (fallback)
 *
 * @return Newly allocated string.  Caller must free().
 */
char *kelp_paths_runtime_dir(void);

/**
 * Return the default gateway Unix domain socket path.
 *
 * Typically <runtime_dir>/kelp.sock.
 *
 * @return Newly allocated string.  Caller must free().
 */
char *kelp_paths_socket(void);

/**
 * Create the config, data, and runtime directories if they do not exist.
 *
 * Equivalent to `mkdir -p` for each directory.
 *
 * @return 0 on success, -1 if any directory could not be created.
 */
int kelp_paths_ensure_dirs(void);

/**
 * Expand a path string, resolving:
 *   - Leading `~` to $HOME
 *   - `${ENV_VAR}` and `${ENV_VAR:-default}` patterns
 *
 * @return Newly allocated string.  Caller must free().
 *         Returns NULL on allocation failure.
 */
char *kelp_paths_expand(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* KELP_PATHS_H */
