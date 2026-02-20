/*
 * clawd-linux :: libclawd-agents
 * sandbox.c - Sandbox lifecycle (orchestrates namespace, seccomp, cgroup, mount)
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/sandbox.h>
#include <clawd/log.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef __linux__

#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

/* Forward declarations for sandbox subsystems */
extern bool clawd_ns_user_ns_available(void);
extern int  clawd_ns_setup_user_mapping(pid_t child_pid, uid_t host_uid, gid_t host_gid);
extern int  clawd_seccomp_apply_filter(void);
extern int  clawd_mount_setup(const char *workspace, const char **readonly_paths, int readonly_count);

/* cgroup interface */
typedef struct clawd_cgroup clawd_cgroup_t;
extern clawd_cgroup_t *clawd_cgroup_create(unsigned int sandbox_id);
extern int  clawd_cgroup_set_memory(clawd_cgroup_t *cg, int limit_mb);
extern int  clawd_cgroup_set_cpu(clawd_cgroup_t *cg, int cores);
extern int  clawd_cgroup_set_pids(clawd_cgroup_t *cg, int max_pids);
extern int  clawd_cgroup_add_pid(clawd_cgroup_t *cg, pid_t pid);
extern void clawd_cgroup_destroy(clawd_cgroup_t *cg);

#define CLONE_FLAGS (CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUSER | \
                     CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWIPC)
#define STACK_SIZE  (1024 * 1024)

static unsigned int next_sandbox_id = 1;

#endif /* __linux__ */

/* ---- Sandbox state ------------------------------------------------------ */

struct clawd_sandbox {
    clawd_sandbox_opts_t opts;
    unsigned int         id;
#ifdef __linux__
    clawd_cgroup_t      *cgroup;
#endif
};

/* ---- Defaults ----------------------------------------------------------- */

void clawd_sandbox_default_opts(clawd_sandbox_opts_t *opts)
{
    if (!opts) return;
    memset(opts, 0, sizeof(*opts));
    opts->memory_limit_mb = 256;
    opts->cpu_cores       = 1;
    opts->max_pids        = 256;
    opts->timeout_sec     = 30;
    opts->enable_network  = false;
    opts->uid_map_host    = getuid();
    opts->gid_map_host    = getgid();
}

/* ---- Availability ------------------------------------------------------- */

bool clawd_sandbox_available(void)
{
#ifdef __linux__
    return clawd_ns_user_ns_available();
#else
    return false;
#endif
}

/* ---- Sandbox lifecycle -------------------------------------------------- */

clawd_sandbox_t *clawd_sandbox_new(const clawd_sandbox_opts_t *opts)
{
    if (!opts) return NULL;

    clawd_sandbox_t *sb = (clawd_sandbox_t *)calloc(1, sizeof(*sb));
    if (!sb) return NULL;

    /* Deep copy options */
    memcpy(&sb->opts, opts, sizeof(*opts));
    if (opts->workspace) {
        sb->opts.workspace = strdup(opts->workspace);
    }
    if (opts->readonly_paths && opts->readonly_count > 0) {
        sb->opts.readonly_paths = (const char **)calloc(
            (size_t)opts->readonly_count, sizeof(char *));
        if (sb->opts.readonly_paths) {
            for (int i = 0; i < opts->readonly_count; i++) {
                sb->opts.readonly_paths[i] =
                    opts->readonly_paths[i] ? strdup(opts->readonly_paths[i]) : NULL;
            }
        }
    }

#ifdef __linux__
    sb->id = next_sandbox_id++;

    /* Create cgroup */
    sb->cgroup = clawd_cgroup_create(sb->id);
    if (sb->cgroup) {
        clawd_cgroup_set_memory(sb->cgroup, sb->opts.memory_limit_mb);
        clawd_cgroup_set_cpu(sb->cgroup, sb->opts.cpu_cores);
        clawd_cgroup_set_pids(sb->cgroup, sb->opts.max_pids);
    }
#endif

    CLAWD_DEBUG("sandbox: created sandbox %u", sb->id);
    return sb;
}

void clawd_sandbox_free(clawd_sandbox_t *sb)
{
    if (!sb) return;

#ifdef __linux__
    if (sb->cgroup) {
        clawd_cgroup_destroy(sb->cgroup);
    }
#endif

    free((void *)sb->opts.workspace);
    if (sb->opts.readonly_paths) {
        for (int i = 0; i < sb->opts.readonly_count; i++) {
            free((void *)sb->opts.readonly_paths[i]);
        }
        free((void *)sb->opts.readonly_paths);
    }
    free(sb);
}

/* ---- Execution ---------------------------------------------------------- */

#ifdef __linux__

typedef struct {
    const char  *cmd;
    char *const *argv;
    const clawd_sandbox_opts_t *opts;
    int          pipe_fd;       /* write end of pipe for signaling parent */
} child_args_t;

static int child_fn(void *arg)
{
    child_args_t *ca = (child_args_t *)arg;

    /* Wait for parent to set up UID/GID mapping */
    close(ca->pipe_fd);

    /* Set up mount namespace */
    clawd_mount_setup(ca->opts->workspace,
                      ca->opts->readonly_paths,
                      ca->opts->readonly_count);

    /* Apply seccomp filter */
    clawd_seccomp_apply_filter();

    /* Execute the command */
    execvp(ca->cmd, ca->argv);

    /* exec failed */
    _exit(127);
}

int clawd_sandbox_exec(clawd_sandbox_t *sb, const char *cmd,
                       char *const argv[], char **output, size_t *output_len)
{
    if (!sb || !cmd) return -1;

    if (output) *output = NULL;
    if (output_len) *output_len = 0;

    /* Create pipe for parent-child synchronization */
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        CLAWD_ERROR("sandbox: pipe() failed: %s", strerror(errno));
        return -1;
    }

    /* Create pipe for capturing output */
    int outfd[2];
    if (pipe(outfd) != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    /* Allocate child stack */
    char *stack = (char *)malloc(STACK_SIZE);
    if (!stack) {
        close(pipefd[0]); close(pipefd[1]);
        close(outfd[0]); close(outfd[1]);
        return -1;
    }

    child_args_t ca = {
        .cmd     = cmd,
        .argv    = argv,
        .opts    = &sb->opts,
        .pipe_fd = pipefd[0],
    };

    /* Clone with namespaces */
    int clone_flags = CLONE_FLAGS | SIGCHLD;
    if (!sb->opts.enable_network) {
        clone_flags |= CLONE_NEWNET;
    }

    pid_t child = clone(child_fn, stack + STACK_SIZE, clone_flags, &ca);
    if (child < 0) {
        CLAWD_ERROR("sandbox: clone() failed: %s", strerror(errno));
        free(stack);
        close(pipefd[0]); close(pipefd[1]);
        close(outfd[0]); close(outfd[1]);
        return -1;
    }

    /* Parent: set up UID/GID mapping */
    close(pipefd[0]);  /* close read end */

    clawd_ns_setup_user_mapping(child,
                                 sb->opts.uid_map_host,
                                 sb->opts.gid_map_host);

    /* Add child to cgroup */
    if (sb->cgroup) {
        clawd_cgroup_add_pid(sb->cgroup, child);
    }

    /* Signal child to proceed */
    close(pipefd[1]);

    /* Close write end of output pipe */
    close(outfd[1]);

    /* Read child output */
    char buf[4096];
    size_t total_len = 0;
    size_t cap = 0;
    char *out_buf = NULL;

    ssize_t n;
    while ((n = read(outfd[0], buf, sizeof(buf))) > 0) {
        if (total_len + (size_t)n >= cap) {
            cap = (cap == 0) ? 4096 : cap * 2;
            if (cap < total_len + (size_t)n + 1) cap = total_len + (size_t)n + 1;
            char *tmp = (char *)realloc(out_buf, cap);
            if (!tmp) break;
            out_buf = tmp;
        }
        memcpy(out_buf + total_len, buf, (size_t)n);
        total_len += (size_t)n;
    }
    close(outfd[0]);

    if (out_buf) {
        out_buf[total_len] = '\0';
    }

    /* Wait for child with timeout */
    int status = 0;
    int timeout_ms = sb->opts.timeout_sec * 1000;

    if (timeout_ms > 0) {
        /* Simple timeout: poll with WNOHANG */
        int elapsed = 0;
        while (elapsed < timeout_ms) {
            pid_t w = waitpid(child, &status, WNOHANG);
            if (w > 0) break;
            if (w < 0) break;
            usleep(10000);  /* 10ms */
            elapsed += 10;
        }

        if (elapsed >= timeout_ms) {
            CLAWD_WARN("sandbox: command timed out after %d seconds", sb->opts.timeout_sec);
            kill(child, SIGKILL);
            waitpid(child, &status, 0);
        }
    } else {
        waitpid(child, &status, 0);
    }

    free(stack);

    if (output) *output = out_buf;
    else free(out_buf);

    if (output_len) *output_len = total_len;

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }

    return -1;
}

#else /* !__linux__ */

int clawd_sandbox_exec(clawd_sandbox_t *sb, const char *cmd,
                       char *const argv[], char **output, size_t *output_len)
{
    (void)sb; (void)cmd; (void)argv;

    CLAWD_ERROR("sandbox: execution not available on this platform");

    if (output) *output = strdup("error: sandbox not available on this platform");
    if (output_len) *output_len = 0;

    return -1;
}

#endif /* __linux__ */
