/*
 * kelp-linux :: libkelp-process
 * process.h - Process management (fork/exec, timeout, kill tree)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_PROCESS_H
#define KELP_PROCESS_H

#include <sys/types.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Process exit result ------------------------------------------------ */

typedef struct kelp_proc_result {
    int    exit_code;
    int    signal;           /* non-zero if killed by signal */
    bool   timed_out;
    char  *stdout_data;
    size_t stdout_len;
    char  *stderr_data;
    size_t stderr_len;
} kelp_proc_result_t;

/* ---- Process options ---------------------------------------------------- */

typedef struct kelp_proc_opts {
    const char    *cmd;            /* command / path to execute              */
    char *const   *argv;           /* argument vector (NULL-terminated)      */
    char *const   *envp;           /* environment (NULL = inherit parent)    */
    const char    *cwd;            /* working directory (NULL = inherit)     */
    const char    *stdin_data;     /* data to write to child stdin           */
    size_t         stdin_len;
    int            timeout_ms;     /* 0 = no timeout                        */
    bool           capture_stdout;
    bool           capture_stderr;
    bool           merge_stderr;   /* redirect stderr into stdout            */
    bool           use_pty;        /* allocate a PTY instead of pipes        */
    bool           set_pgid;       /* call setpgid so kill_tree works        */
} kelp_proc_opts_t;

/* ---- API ---------------------------------------------------------------- */

/**
 * Execute a command synchronously, capturing output.
 *
 * Forks, optionally sets up pipes/PTY, exec's the command, waits for exit
 * or timeout, and populates `result`.  Returns 0 on success (the process
 * ran -- check result->exit_code), or -1 on internal failure (fork, pipe, etc.).
 */
int kelp_proc_exec(const kelp_proc_opts_t *opts, kelp_proc_result_t *result);

/**
 * Spawn a command asynchronously (does not wait).
 *
 * Returns the child PID on success, or (pid_t)-1 on failure.
 */
pid_t kelp_proc_spawn(const kelp_proc_opts_t *opts);

/**
 * Wait for a previously-spawned child to exit, with optional timeout.
 *
 * Returns 0 on success, -1 on error.
 */
int kelp_proc_wait(pid_t pid, int timeout_ms, kelp_proc_result_t *result);

/**
 * Send a signal to a single process.
 *
 * Returns 0 on success, -1 on failure (sets errno).
 */
int kelp_proc_kill(pid_t pid, int sig);

/**
 * Kill an entire process group.
 *
 * When the child was spawned with set_pgid=true the child's PID is also
 * its PGID.  This sends `sig` to every process in the group.
 * Returns 0 on success, -1 on failure.
 */
int kelp_proc_kill_tree(pid_t pid, int sig);

/**
 * Free dynamically allocated fields inside a result struct.
 */
void kelp_proc_result_free(kelp_proc_result_t *result);

/**
 * Check whether a process is still running (via kill(pid, 0)).
 */
bool kelp_proc_is_running(pid_t pid);

#ifdef __cplusplus
}
#endif

#endif /* KELP_PROCESS_H */
