/*
 * kelp-linux :: libkelp-process
 * supervisor.h - Process supervisor with auto-restart
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_SUPERVISOR_H
#define KELP_SUPERVISOR_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opaque supervisor handle.
 */
typedef struct kelp_supervisor kelp_supervisor_t;

/**
 * Descriptor for a supervised child process.
 */
typedef struct kelp_supervised {
    const char    *name;             /* unique name for this entry        */
    const char    *cmd;              /* executable path                   */
    char *const   *argv;            /* argument vector (NULL-terminated)  */
    int            restart_delay_ms; /* minimum delay before restart      */
    int            max_restarts;     /* 0 = unlimited                     */
    bool           auto_restart;     /* restart on unexpected exit?       */
} kelp_supervised_t;

/**
 * Create a new (empty) supervisor.
 *
 * Returns NULL on allocation failure.
 */
kelp_supervisor_t *kelp_supervisor_new(void);

/**
 * Destroy the supervisor, stopping all children first.
 */
void kelp_supervisor_free(kelp_supervisor_t *sv);

/**
 * Register a process to be supervised.
 *
 * The supervisor copies all necessary data from `proc`.
 * Returns 0 on success, -1 on failure.
 */
int kelp_supervisor_add(kelp_supervisor_t *sv, const kelp_supervised_t *proc);

/**
 * Start all registered processes.
 *
 * Returns 0 on success, -1 if any process fails to start.
 */
int kelp_supervisor_start(kelp_supervisor_t *sv);

/**
 * Stop all supervised processes (SIGTERM, then SIGKILL after grace period).
 */
void kelp_supervisor_stop(kelp_supervisor_t *sv);

/**
 * Restart a single supervised process by name.
 *
 * Returns 0 on success, -1 if the name is not found or restart fails.
 */
int kelp_supervisor_restart(kelp_supervisor_t *sv, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* KELP_SUPERVISOR_H */
