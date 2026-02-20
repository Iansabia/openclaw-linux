/*
 * clawd-linux :: libclawd-process
 * process.c - Fork/exec with timeout, pipe capture, process-tree killing
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/process.h>
#include <clawd/pty.h>
#include <clawd/log.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/wait.h>

#ifdef __linux__
#include <sys/timerfd.h>
#endif

/* ---- internal helpers --------------------------------------------------- */

/** Set a file descriptor to non-blocking mode. */
static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/** Set close-on-exec on a file descriptor. */
static int set_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

/**
 * Grow a dynamically allocated buffer.
 * *buf / *len / *cap follow the usual (malloc, used, capacity) triple.
 */
static int grow_buf(char **buf, size_t *len, size_t *cap, const char *data,
                    size_t n)
{
    if (n == 0)
        return 0;

    if (*len + n > *cap) {
        size_t new_cap = *cap ? *cap : 4096;
        while (new_cap < *len + n)
            new_cap *= 2;
        char *tmp = realloc(*buf, new_cap);
        if (!tmp)
            return -1;
        *buf = tmp;
        *cap = new_cap;
    }
    memcpy(*buf + *len, data, n);
    *len += n;
    return 0;
}

/**
 * Create a timer file descriptor that fires once after `ms` milliseconds.
 * On macOS this returns -1 (timer handled via poll timeout instead).
 */
static int create_timer_fd(int ms)
{
#ifdef __linux__
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (tfd < 0)
        return -1;

    struct itimerspec its = {0};
    its.it_value.tv_sec  = ms / 1000;
    its.it_value.tv_nsec = (ms % 1000) * 1000000L;

    if (timerfd_settime(tfd, 0, &its, NULL) < 0) {
        close(tfd);
        return -1;
    }
    return tfd;
#else
    (void)ms;
    return -1;  /* macOS: use poll() timeout instead */
#endif
}

/**
 * Perform the child-side setup after fork() and before exec().
 * This runs in the forked child -- only async-signal-safe functions are legal.
 */
static void child_setup(const clawd_proc_opts_t *opts,
                         int stdin_rd,  int stdout_wr, int stderr_wr)
{
    /* New session / process group */
    if (opts->set_pgid) {
        setpgid(0, 0);
    }

    /* Working directory */
    if (opts->cwd) {
        if (chdir(opts->cwd) < 0)
            _exit(127);
    }

    /* Wire up stdin */
    if (stdin_rd >= 0) {
        dup2(stdin_rd, STDIN_FILENO);
        close(stdin_rd);
    }

    /* Wire up stdout */
    if (stdout_wr >= 0) {
        dup2(stdout_wr, STDOUT_FILENO);
        close(stdout_wr);
    }

    /* Wire up stderr */
    if (opts->merge_stderr && stdout_wr >= 0) {
        dup2(STDOUT_FILENO, STDERR_FILENO);
    } else if (stderr_wr >= 0) {
        dup2(stderr_wr, STDERR_FILENO);
        close(stderr_wr);
    }

    /* Exec */
    if (opts->envp) {
        execve(opts->cmd, opts->argv, opts->envp);
    } else {
        execvp(opts->cmd, opts->argv);
    }

    /* If exec fails, exit with 127 (command-not-found convention) */
    _exit(127);
}

/**
 * Drain pipe fds into buffers using poll(), with optional timeout.
 *
 * Returns  0 on normal completion (all fds hit EOF / child exited).
 * Returns  1 if the timeout fired.
 * Returns -1 on fatal poll() error.
 */
static int drain_pipes(int stdout_fd, int stderr_fd, int timer_fd,
                       int timeout_ms,
                       char **out_buf, size_t *out_len, size_t *out_cap,
                       char **err_buf, size_t *err_len, size_t *err_cap)
{
    char tmp[8192];
    bool timed_out = false;

    for (;;) {
        struct pollfd fds[3];
        int nfds = 0;

        if (stdout_fd >= 0) {
            fds[nfds].fd      = stdout_fd;
            fds[nfds].events  = POLLIN;
            fds[nfds].revents = 0;
            nfds++;
        }
        if (stderr_fd >= 0) {
            fds[nfds].fd      = stderr_fd;
            fds[nfds].events  = POLLIN;
            fds[nfds].revents = 0;
            nfds++;
        }
#ifdef __linux__
        if (timer_fd >= 0) {
            fds[nfds].fd      = timer_fd;
            fds[nfds].events  = POLLIN;
            fds[nfds].revents = 0;
            nfds++;
        }
#endif
        if (nfds == 0)
            break;

        /*
         * On macOS (no timerfd) use the poll timeout directly.
         * On Linux the timerfd is in the pollset so we can use -1.
         */
        int poll_timeout;
#ifdef __linux__
        poll_timeout = (timer_fd >= 0) ? -1 : -1;
        (void)timeout_ms;
#else
        poll_timeout = (timeout_ms > 0) ? timeout_ms : -1;
#endif

        int ret = poll(fds, (nfds_t)nfds, poll_timeout);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (ret == 0) {
            /* macOS: poll timeout expired */
            timed_out = true;
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (fds[i].revents == 0)
                continue;

#ifdef __linux__
            /* Timer fired? */
            if (fds[i].fd == timer_fd && (fds[i].revents & POLLIN)) {
                uint64_t expirations;
                (void)read(timer_fd, &expirations, sizeof(expirations));
                timed_out = true;
                goto done;
            }
#endif

            if (fds[i].revents & (POLLIN | POLLHUP)) {
                ssize_t n = read(fds[i].fd, tmp, sizeof(tmp));
                if (n > 0) {
                    if (fds[i].fd == stdout_fd && out_buf) {
                        grow_buf(out_buf, out_len, out_cap, tmp, (size_t)n);
                    } else if (fds[i].fd == stderr_fd && err_buf) {
                        grow_buf(err_buf, err_len, err_cap, tmp, (size_t)n);
                    }
                } else if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR)) {
                    /* EOF or fatal read error -- stop watching this fd */
                    if (fds[i].fd == stdout_fd) stdout_fd = -1;
                    if (fds[i].fd == stderr_fd) stderr_fd = -1;
                }
            }

            if (fds[i].revents & (POLLERR | POLLNVAL)) {
                if (fds[i].fd == stdout_fd) stdout_fd = -1;
                if (fds[i].fd == stderr_fd) stderr_fd = -1;
            }
        }
    }

#ifdef __linux__
done:
#endif
    return timed_out ? 1 : 0;
}

/**
 * Reap the child, populating exit_code / signal in result.
 */
static void reap_child(pid_t pid, clawd_proc_result_t *result)
{
    int status = 0;
    pid_t w;

    do {
        w = waitpid(pid, &status, 0);
    } while (w < 0 && errno == EINTR);

    if (w > 0) {
        if (WIFEXITED(status)) {
            result->exit_code = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            result->signal = WTERMSIG(status);
            result->exit_code = 128 + result->signal;
        }
    }
}

/**
 * Kill a process tree with escalation: first send `sig`, wait briefly,
 * then SIGKILL if the process is still alive.
 */
static void kill_with_escalation(pid_t pid, bool has_pgid)
{
    int grace_ms = 500;  /* half a second before SIGKILL */

    if (has_pgid) {
        kill(-pid, SIGTERM);
    } else {
        kill(pid, SIGTERM);
    }

    /* Brief wait to see if the process exits voluntarily */
    struct timespec ts = {
        .tv_sec  = grace_ms / 1000,
        .tv_nsec = (grace_ms % 1000) * 1000000L
    };
    nanosleep(&ts, NULL);

    /* Check if still alive */
    if (kill(pid, 0) == 0) {
        if (has_pgid) {
            kill(-pid, SIGKILL);
        } else {
            kill(pid, SIGKILL);
        }
    }
}

/* ---- public API --------------------------------------------------------- */

int clawd_proc_exec(const clawd_proc_opts_t *opts, clawd_proc_result_t *result)
{
    if (!opts || !opts->cmd || !result)
        return -1;

    memset(result, 0, sizeof(*result));

    /* Pipe pairs: [0]=read, [1]=write */
    int stdin_pipe[2]  = {-1, -1};
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};

    /* PTY (if requested) */
    clawd_pty_t pty = {0};
    pty.master_fd = -1;
    pty.slave_fd  = -1;

    if (opts->use_pty) {
        if (clawd_pty_open(&pty) < 0) {
            CLAWD_ERROR("pty open failed: %s", strerror(errno));
            return -1;
        }
    } else {
        /* Set up stdin pipe if we have data to feed */
        if (opts->stdin_data && opts->stdin_len > 0) {
            if (pipe(stdin_pipe) < 0) {
                CLAWD_ERROR("pipe(stdin) failed: %s", strerror(errno));
                return -1;
            }
            set_cloexec(stdin_pipe[0]);
            set_cloexec(stdin_pipe[1]);
        }

        /* Set up stdout pipe */
        if (opts->capture_stdout) {
            if (pipe(stdout_pipe) < 0) {
                CLAWD_ERROR("pipe(stdout) failed: %s", strerror(errno));
                goto err_close;
            }
            set_cloexec(stdout_pipe[0]);
            set_cloexec(stdout_pipe[1]);
            set_nonblock(stdout_pipe[0]);
        }

        /* Set up stderr pipe (unless merged) */
        if (opts->capture_stderr && !opts->merge_stderr) {
            if (pipe(stderr_pipe) < 0) {
                CLAWD_ERROR("pipe(stderr) failed: %s", strerror(errno));
                goto err_close;
            }
            set_cloexec(stderr_pipe[0]);
            set_cloexec(stderr_pipe[1]);
            set_nonblock(stderr_pipe[0]);
        }
    }

    /* ---- fork ----------------------------------------------------------- */

    pid_t pid;

    if (opts->use_pty) {
        pid = clawd_pty_fork(&pty, opts->cmd, opts->argv);
        if (pid < 0) {
            CLAWD_ERROR("pty_fork failed: %s", strerror(errno));
            clawd_pty_close(&pty);
            return -1;
        }
        if (pid == 0) {
            /* child -- clawd_pty_fork already exec'd */
            _exit(127);  /* unreachable */
        }
        /* For PTY, master_fd serves as both stdout and stdin */
        set_nonblock(pty.master_fd);
    } else {
        pid = fork();
        if (pid < 0) {
            CLAWD_ERROR("fork failed: %s", strerror(errno));
            goto err_close;
        }

        if (pid == 0) {
            /* ---------- child process ---------- */

            /* Close parent ends of pipes */
            if (stdin_pipe[1] >= 0)  close(stdin_pipe[1]);
            if (stdout_pipe[0] >= 0) close(stdout_pipe[0]);
            if (stderr_pipe[0] >= 0) close(stderr_pipe[0]);

            child_setup(opts, stdin_pipe[0], stdout_pipe[1], stderr_pipe[1]);
            /* NOTREACHED */
            _exit(127);
        }
    }

    /* ---------- parent process ---------- */

    /* Close child ends of pipes */
    if (stdin_pipe[0] >= 0)  { close(stdin_pipe[0]);  stdin_pipe[0]  = -1; }
    if (stdout_pipe[1] >= 0) { close(stdout_pipe[1]); stdout_pipe[1] = -1; }
    if (stderr_pipe[1] >= 0) { close(stderr_pipe[1]); stderr_pipe[1] = -1; }

    /* Write stdin data to child */
    if (!opts->use_pty && opts->stdin_data && opts->stdin_len > 0 &&
        stdin_pipe[1] >= 0) {
        size_t off = 0;
        while (off < opts->stdin_len) {
            ssize_t w = write(stdin_pipe[1], opts->stdin_data + off,
                              opts->stdin_len - off);
            if (w < 0) {
                if (errno == EINTR) continue;
                break;
            }
            off += (size_t)w;
        }
        close(stdin_pipe[1]);
        stdin_pipe[1] = -1;
    } else if (stdin_pipe[1] >= 0) {
        close(stdin_pipe[1]);
        stdin_pipe[1] = -1;
    }

    /* Create timer for timeout */
    int timer_fd = -1;
    if (opts->timeout_ms > 0) {
        timer_fd = create_timer_fd(opts->timeout_ms);
        /* On macOS timer_fd will be -1; timeout handled via poll() */
    }

    /* Determine which fds to drain */
    int out_fd = -1;
    int err_fd = -1;

    if (opts->use_pty) {
        out_fd = pty.master_fd;
    } else {
        out_fd = stdout_pipe[0];
        err_fd = stderr_pipe[0];
    }

    /* Drain output from child */
    size_t out_cap = 0;
    size_t err_cap = 0;

    int drain_rc = drain_pipes(
        out_fd, err_fd, timer_fd, opts->timeout_ms,
        opts->capture_stdout ? &result->stdout_data : NULL,
        &result->stdout_len, &out_cap,
        (opts->capture_stderr && !opts->merge_stderr) ? &result->stderr_data : NULL,
        &result->stderr_len, &err_cap);

    if (drain_rc == 1) {
        /* Timeout occurred */
        result->timed_out = true;
        CLAWD_WARN("process %d timed out after %d ms", (int)pid,
                   opts->timeout_ms);
        kill_with_escalation(pid, opts->set_pgid);
    }

    /* Clean up fds */
    if (stdout_pipe[0] >= 0) close(stdout_pipe[0]);
    if (stderr_pipe[0] >= 0) close(stderr_pipe[0]);
    if (timer_fd >= 0)       close(timer_fd);
    if (opts->use_pty)       clawd_pty_close(&pty);

    /* Reap child */
    reap_child(pid, result);

    /* NUL-terminate captured output for convenience */
    if (result->stdout_data && result->stdout_len > 0) {
        char *tmp = realloc(result->stdout_data, result->stdout_len + 1);
        if (tmp) {
            tmp[result->stdout_len] = '\0';
            result->stdout_data = tmp;
        }
    }
    if (result->stderr_data && result->stderr_len > 0) {
        char *tmp = realloc(result->stderr_data, result->stderr_len + 1);
        if (tmp) {
            tmp[result->stderr_len] = '\0';
            result->stderr_data = tmp;
        }
    }

    return 0;

err_close:
    if (stdin_pipe[0] >= 0)  close(stdin_pipe[0]);
    if (stdin_pipe[1] >= 0)  close(stdin_pipe[1]);
    if (stdout_pipe[0] >= 0) close(stdout_pipe[0]);
    if (stdout_pipe[1] >= 0) close(stdout_pipe[1]);
    if (stderr_pipe[0] >= 0) close(stderr_pipe[0]);
    if (stderr_pipe[1] >= 0) close(stderr_pipe[1]);
    return -1;
}

pid_t clawd_proc_spawn(const clawd_proc_opts_t *opts)
{
    if (!opts || !opts->cmd)
        return (pid_t)-1;

    pid_t pid = fork();
    if (pid < 0)
        return (pid_t)-1;

    if (pid == 0) {
        /* child */
        if (opts->set_pgid)
            setpgid(0, 0);

        if (opts->cwd && chdir(opts->cwd) < 0)
            _exit(127);

        if (opts->envp)
            execve(opts->cmd, opts->argv, opts->envp);
        else
            execvp(opts->cmd, opts->argv);

        _exit(127);
    }

    return pid;
}

int clawd_proc_wait(pid_t pid, int timeout_ms, clawd_proc_result_t *result)
{
    if (pid <= 0 || !result)
        return -1;

    memset(result, 0, sizeof(*result));

    if (timeout_ms <= 0) {
        /* Blocking wait */
        reap_child(pid, result);
        return 0;
    }

    /*
     * Poll-based wait with timeout.
     * We poll in short intervals until the child exits or we time out.
     */
    int elapsed_ms = 0;
    int interval_ms = 10;  /* check every 10ms */

    while (elapsed_ms < timeout_ms) {
        int status = 0;
        pid_t w = waitpid(pid, &status, WNOHANG);

        if (w > 0) {
            if (WIFEXITED(status)) {
                result->exit_code = WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                result->signal = WTERMSIG(status);
                result->exit_code = 128 + result->signal;
            }
            return 0;
        }

        if (w < 0 && errno != EINTR) {
            return -1;  /* waitpid error (ECHILD etc.) */
        }

        struct timespec ts = {
            .tv_sec  = interval_ms / 1000,
            .tv_nsec = (interval_ms % 1000) * 1000000L
        };
        nanosleep(&ts, NULL);
        elapsed_ms += interval_ms;
    }

    /* Timed out */
    result->timed_out = true;
    return 0;
}

int clawd_proc_kill(pid_t pid, int sig)
{
    if (pid <= 0)
        return -1;
    return kill(pid, sig);
}

int clawd_proc_kill_tree(pid_t pid, int sig)
{
    if (pid <= 0)
        return -1;
    /* Send to the process group: -pid targets all processes in the group
     * whose PGID equals pid (set by setpgid(0,0) in the child). */
    return kill(-pid, sig);
}

void clawd_proc_result_free(clawd_proc_result_t *result)
{
    if (!result)
        return;

    free(result->stdout_data);
    free(result->stderr_data);
    memset(result, 0, sizeof(*result));
}

bool clawd_proc_is_running(pid_t pid)
{
    if (pid <= 0)
        return false;
    /* kill(pid, 0) succeeds if the process exists and we have permission */
    return kill(pid, 0) == 0;
}
