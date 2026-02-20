/*
 * clawd-linux :: libclawd-process
 * supervisor.c - Process supervisor with auto-restart and backoff
 *
 * Tracks child processes, detects exits via waitpid(WNOHANG), and
 * automatically restarts children that die unexpectedly with
 * exponential backoff.
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/supervisor.h>
#include <clawd/process.h>
#include <clawd/log.h>

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/wait.h>

/* ---- constants ---------------------------------------------------------- */

#define SV_MAX_ENTRIES       64
#define SV_KILL_GRACE_MS    3000     /* SIGTERM -> SIGKILL grace period */
#define SV_BACKOFF_MAX_MS   30000    /* maximum backoff delay */

/* ---- internal entry state ----------------------------------------------- */

typedef enum {
    SV_STATE_STOPPED = 0,
    SV_STATE_RUNNING,
    SV_STATE_BACKOFF,   /* waiting before restart */
    SV_STATE_FATAL      /* exceeded max_restarts  */
} sv_state_t;

typedef struct {
    /* Configuration (copied from clawd_supervised_t) */
    char         *name;
    char         *cmd;
    char        **argv;     /* NULL-terminated, deep copy */
    int           restart_delay_ms;
    int           max_restarts;
    bool          auto_restart;

    /* Runtime state */
    sv_state_t    state;
    pid_t         pid;
    int           restart_count;
    int           current_backoff_ms;
    struct timespec next_restart;   /* when to attempt the next restart */
} sv_entry_t;

struct clawd_supervisor {
    sv_entry_t  entries[SV_MAX_ENTRIES];
    int         count;
    bool        running;     /* true between start() and stop() */
};

/* ---- helpers ------------------------------------------------------------ */

/** Deep-copy a NULL-terminated argv array. */
static char **argv_dup(char *const *argv)
{
    if (!argv)
        return NULL;

    int n = 0;
    while (argv[n]) n++;

    char **copy = calloc((size_t)(n + 1), sizeof(char *));
    if (!copy)
        return NULL;

    for (int i = 0; i < n; i++) {
        copy[i] = strdup(argv[i]);
        if (!copy[i]) {
            for (int j = 0; j < i; j++) free(copy[j]);
            free(copy);
            return NULL;
        }
    }
    copy[n] = NULL;
    return copy;
}

/** Free a deep-copied argv array. */
static void argv_free(char **argv)
{
    if (!argv) return;
    for (int i = 0; argv[i]; i++)
        free(argv[i]);
    free(argv);
}

/** Free all resources owned by an sv_entry_t. */
static void entry_free(sv_entry_t *e)
{
    free(e->name);
    free(e->cmd);
    argv_free(e->argv);
    memset(e, 0, sizeof(*e));
}

/** Get the current monotonic time. */
static void now_monotonic(struct timespec *ts)
{
#ifdef CLOCK_MONOTONIC
    clock_gettime(CLOCK_MONOTONIC, ts);
#else
    /* Fallback for systems without CLOCK_MONOTONIC */
    clock_gettime(CLOCK_REALTIME, ts);
#endif
}

/** Add milliseconds to a timespec. */
static void timespec_add_ms(struct timespec *ts, int ms)
{
    ts->tv_sec  += ms / 1000;
    ts->tv_nsec += (ms % 1000) * 1000000L;
    if (ts->tv_nsec >= 1000000000L) {
        ts->tv_sec++;
        ts->tv_nsec -= 1000000000L;
    }
}

/** Return true if `a` is before or equal to `b`. */
static bool timespec_le(const struct timespec *a, const struct timespec *b)
{
    if (a->tv_sec < b->tv_sec) return true;
    if (a->tv_sec > b->tv_sec) return false;
    return a->tv_nsec <= b->tv_nsec;
}

/** Spawn a child process for the given entry. */
static int spawn_entry(sv_entry_t *e)
{
    clawd_proc_opts_t opts = {0};
    opts.cmd      = e->cmd;
    opts.argv     = e->argv;
    opts.set_pgid = true;   /* so we can kill_tree later */

    pid_t pid = clawd_proc_spawn(&opts);
    if (pid < 0) {
        CLAWD_ERROR("supervisor: failed to spawn '%s': %s",
                    e->name, strerror(errno));
        return -1;
    }

    e->pid   = pid;
    e->state = SV_STATE_RUNNING;
    CLAWD_INFO("supervisor: started '%s' (pid %d)", e->name, (int)pid);
    return 0;
}

/** Send SIGTERM then SIGKILL to a supervised child. */
static void stop_entry(sv_entry_t *e)
{
    if (e->state != SV_STATE_RUNNING || e->pid <= 0)
        return;

    CLAWD_INFO("supervisor: stopping '%s' (pid %d)", e->name, (int)e->pid);

    /* Send SIGTERM to the process group */
    clawd_proc_kill_tree(e->pid, SIGTERM);

    /* Wait up to SV_KILL_GRACE_MS for the child to exit */
    int elapsed = 0;
    int interval = 50;

    while (elapsed < SV_KILL_GRACE_MS) {
        int status;
        pid_t w = waitpid(e->pid, &status, WNOHANG);
        if (w > 0 || (w < 0 && errno == ECHILD))
            goto reaped;

        struct timespec ts = {
            .tv_sec  = interval / 1000,
            .tv_nsec = (interval % 1000) * 1000000L
        };
        nanosleep(&ts, NULL);
        elapsed += interval;
    }

    /* Still alive -- SIGKILL */
    CLAWD_WARN("supervisor: '%s' did not exit, sending SIGKILL", e->name);
    clawd_proc_kill_tree(e->pid, SIGKILL);
    waitpid(e->pid, NULL, 0);

reaped:
    e->pid   = 0;
    e->state = SV_STATE_STOPPED;
}

/**
 * Check for exited children (non-blocking) and handle restarts.
 */
static void check_children(clawd_supervisor_t *sv)
{
    for (int i = 0; i < sv->count; i++) {
        sv_entry_t *e = &sv->entries[i];

        /* Check running entries for exit */
        if (e->state == SV_STATE_RUNNING && e->pid > 0) {
            int status;
            pid_t w = waitpid(e->pid, &status, WNOHANG);

            if (w > 0) {
                int code = -1;
                if (WIFEXITED(status))
                    code = WEXITSTATUS(status);
                else if (WIFSIGNALED(status))
                    code = 128 + WTERMSIG(status);

                CLAWD_WARN("supervisor: '%s' (pid %d) exited with code %d",
                           e->name, (int)e->pid, code);
                e->pid = 0;

                if (!e->auto_restart) {
                    e->state = SV_STATE_STOPPED;
                    continue;
                }

                e->restart_count++;

                if (e->max_restarts > 0 &&
                    e->restart_count >= e->max_restarts) {
                    CLAWD_ERROR("supervisor: '%s' reached max restarts (%d)",
                                e->name, e->max_restarts);
                    e->state = SV_STATE_FATAL;
                    continue;
                }

                /* Schedule restart with exponential backoff */
                e->current_backoff_ms = e->restart_delay_ms;
                if (e->restart_count > 1) {
                    e->current_backoff_ms *= (1 << (e->restart_count - 1));
                    if (e->current_backoff_ms > SV_BACKOFF_MAX_MS)
                        e->current_backoff_ms = SV_BACKOFF_MAX_MS;
                }

                now_monotonic(&e->next_restart);
                timespec_add_ms(&e->next_restart, e->current_backoff_ms);
                e->state = SV_STATE_BACKOFF;

                CLAWD_INFO("supervisor: will restart '%s' in %d ms "
                           "(attempt %d)",
                           e->name, e->current_backoff_ms,
                           e->restart_count + 1);

            } else if (w < 0 && errno == ECHILD) {
                /* Child disappeared without us noticing */
                e->pid   = 0;
                e->state = SV_STATE_STOPPED;
            }
        }

        /* Check backoff entries for restart time */
        if (e->state == SV_STATE_BACKOFF) {
            struct timespec now;
            now_monotonic(&now);

            if (timespec_le(&e->next_restart, &now)) {
                CLAWD_INFO("supervisor: restarting '%s'", e->name);
                if (spawn_entry(e) < 0) {
                    e->state = SV_STATE_FATAL;
                }
            }
        }
    }
}

/* ---- public API --------------------------------------------------------- */

clawd_supervisor_t *clawd_supervisor_new(void)
{
    clawd_supervisor_t *sv = calloc(1, sizeof(*sv));
    if (!sv)
        return NULL;

    CLAWD_TRACE("supervisor created");
    return sv;
}

void clawd_supervisor_free(clawd_supervisor_t *sv)
{
    if (!sv)
        return;

    /* Stop all running children */
    clawd_supervisor_stop(sv);

    /* Free entry resources */
    for (int i = 0; i < sv->count; i++)
        entry_free(&sv->entries[i]);

    CLAWD_TRACE("supervisor freed");
    free(sv);
}

int clawd_supervisor_add(clawd_supervisor_t *sv, const clawd_supervised_t *proc)
{
    if (!sv || !proc || !proc->name || !proc->cmd)
        return -1;

    if (sv->count >= SV_MAX_ENTRIES) {
        CLAWD_ERROR("supervisor: max entries (%d) reached", SV_MAX_ENTRIES);
        return -1;
    }

    /* Check for duplicate name */
    for (int i = 0; i < sv->count; i++) {
        if (strcmp(sv->entries[i].name, proc->name) == 0) {
            CLAWD_ERROR("supervisor: duplicate name '%s'", proc->name);
            return -1;
        }
    }

    sv_entry_t *e = &sv->entries[sv->count];
    memset(e, 0, sizeof(*e));

    e->name = strdup(proc->name);
    e->cmd  = strdup(proc->cmd);
    if (!e->name || !e->cmd) {
        free(e->name);
        free(e->cmd);
        return -1;
    }

    e->argv = argv_dup(proc->argv);
    if (proc->argv && !e->argv) {
        free(e->name);
        free(e->cmd);
        return -1;
    }

    e->restart_delay_ms  = proc->restart_delay_ms > 0 ? proc->restart_delay_ms
                                                       : 1000;
    e->max_restarts      = proc->max_restarts;
    e->auto_restart      = proc->auto_restart;
    e->state             = SV_STATE_STOPPED;
    e->current_backoff_ms = e->restart_delay_ms;

    sv->count++;
    CLAWD_INFO("supervisor: added '%s' (%s)", e->name, e->cmd);
    return 0;
}

int clawd_supervisor_start(clawd_supervisor_t *sv)
{
    if (!sv)
        return -1;

    sv->running = true;
    int failures = 0;

    for (int i = 0; i < sv->count; i++) {
        sv_entry_t *e = &sv->entries[i];
        if (e->state == SV_STATE_STOPPED) {
            e->restart_count = 0;
            if (spawn_entry(e) < 0)
                failures++;
        }
    }

    CLAWD_INFO("supervisor: started %d/%d processes",
               sv->count - failures, sv->count);

    /*
     * Run a monitoring loop.
     * In a production system this would be integrated into the main event
     * loop.  Here we do a single pass of check_children() to demonstrate
     * the functionality and make start() non-blocking.
     */
    check_children(sv);

    return failures > 0 ? -1 : 0;
}

void clawd_supervisor_stop(clawd_supervisor_t *sv)
{
    if (!sv)
        return;

    sv->running = false;

    for (int i = 0; i < sv->count; i++) {
        sv_entry_t *e = &sv->entries[i];
        if (e->state == SV_STATE_RUNNING)
            stop_entry(e);
        else
            e->state = SV_STATE_STOPPED;
    }

    CLAWD_INFO("supervisor: all processes stopped");
}

int clawd_supervisor_restart(clawd_supervisor_t *sv, const char *name)
{
    if (!sv || !name)
        return -1;

    for (int i = 0; i < sv->count; i++) {
        sv_entry_t *e = &sv->entries[i];
        if (strcmp(e->name, name) == 0) {
            /* Stop if running */
            if (e->state == SV_STATE_RUNNING)
                stop_entry(e);

            /* Reset counters */
            e->restart_count      = 0;
            e->current_backoff_ms = e->restart_delay_ms;
            e->state              = SV_STATE_STOPPED;

            return spawn_entry(e);
        }
    }

    CLAWD_ERROR("supervisor: process '%s' not found", name);
    return -1;
}
