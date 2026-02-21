/*
 * kelp-linux :: libkelp-agents
 * sandbox.h - Linux kernel sandboxing (namespaces, seccomp, cgroups)
 *
 * Uses user namespaces, mount namespaces, PID namespaces, seccomp-BPF,
 * and cgroup v2 to create isolated execution environments for tools.
 *
 * On non-Linux platforms, all functions are available but sandboxing
 * is reported as unavailable via kelp_sandbox_available().
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_SANDBOX_H
#define KELP_SANDBOX_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Sandbox options ---------------------------------------------------- */

typedef struct kelp_sandbox_opts {
    const char  *workspace;          /* bind-mount read-write */
    const char **readonly_paths;     /* additional read-only mounts */
    int          readonly_count;
    int          memory_limit_mb;    /* cgroup memory limit (default 256) */
    int          cpu_cores;          /* cgroup CPU limit (default 1) */
    int          max_pids;           /* cgroup PID limit (default 256) */
    int          timeout_sec;        /* execution timeout */
    bool         enable_network;     /* allow network access (default false) */
    uid_t        uid_map_host;       /* UID mapping in user namespace */
    gid_t        gid_map_host;       /* GID mapping in user namespace */
} kelp_sandbox_opts_t;

/* ---- Opaque handle ------------------------------------------------------ */

typedef struct kelp_sandbox kelp_sandbox_t;

/* ---- API ---------------------------------------------------------------- */

/**
 * Create a new sandbox instance.
 *
 * On Linux, this prepares namespace and cgroup resources.
 * On other platforms, this returns a handle that will report errors
 * if execution is attempted.
 *
 * @param opts  Sandbox options.
 * @return Sandbox handle, or NULL on allocation failure.
 */
kelp_sandbox_t *kelp_sandbox_new(const kelp_sandbox_opts_t *opts);

/**
 * Free a sandbox and clean up all associated resources (cgroups, etc.).
 *
 * @param sb  Sandbox handle (may be NULL).
 */
void kelp_sandbox_free(kelp_sandbox_t *sb);

/**
 * Execute a command inside the sandbox.
 *
 * @param sb          Sandbox handle.
 * @param cmd         Command to execute.
 * @param argv        Argument vector (NULL-terminated).
 * @param output      Output: receives a malloc'd buffer with stdout+stderr.
 * @param output_len  Output: set to the length of the output buffer.
 * @return The child's exit code, or -1 on internal error.
 */
int kelp_sandbox_exec(kelp_sandbox_t *sb, const char *cmd,
                       char *const argv[], char **output, size_t *output_len);

/**
 * Check whether kernel sandboxing is available on this system.
 *
 * Returns true if user namespaces are enabled (Linux-specific).
 * Always returns false on non-Linux platforms.
 */
bool kelp_sandbox_available(void);

/**
 * Fill a sandbox options struct with sensible defaults.
 *
 * Defaults:
 *   memory_limit_mb = 256
 *   cpu_cores       = 1
 *   max_pids        = 256
 *   timeout_sec     = 30
 *   enable_network  = false
 *
 * @param opts  Options struct to populate.
 */
void kelp_sandbox_default_opts(kelp_sandbox_opts_t *opts);

#ifdef __cplusplus
}
#endif

#endif /* KELP_SANDBOX_H */
