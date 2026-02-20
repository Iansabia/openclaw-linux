/*
 * clawd-linux :: libclawd-process
 * supervisor.h - Process supervisor with auto-restart
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_SUPERVISOR_H
#define CLAWD_SUPERVISOR_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opaque supervisor handle.
 */
typedef struct clawd_supervisor clawd_supervisor_t;

/**
 * Descriptor for a supervised child process.
 */
typedef struct clawd_supervised {
    const char    *name;             /* unique name for this entry        */
    const char    *cmd;              /* executable path                   */
    char *const   *argv;            /* argument vector (NULL-terminated)  */
    int            restart_delay_ms; /* minimum delay before restart      */
    int            max_restarts;     /* 0 = unlimited                     */
    bool           auto_restart;     /* restart on unexpected exit?       */
} clawd_supervised_t;

/**
 * Create a new (empty) supervisor.
 *
 * Returns NULL on allocation failure.
 */
clawd_supervisor_t *clawd_supervisor_new(void);

/**
 * Destroy the supervisor, stopping all children first.
 */
void clawd_supervisor_free(clawd_supervisor_t *sv);

/**
 * Register a process to be supervised.
 *
 * The supervisor copies all necessary data from `proc`.
 * Returns 0 on success, -1 on failure.
 */
int clawd_supervisor_add(clawd_supervisor_t *sv, const clawd_supervised_t *proc);

/**
 * Start all registered processes.
 *
 * Returns 0 on success, -1 if any process fails to start.
 */
int clawd_supervisor_start(clawd_supervisor_t *sv);

/**
 * Stop all supervised processes (SIGTERM, then SIGKILL after grace period).
 */
void clawd_supervisor_stop(clawd_supervisor_t *sv);

/**
 * Restart a single supervised process by name.
 *
 * Returns 0 on success, -1 if the name is not found or restart fails.
 */
int clawd_supervisor_restart(clawd_supervisor_t *sv, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_SUPERVISOR_H */
