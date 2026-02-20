/*
 * clawd-linux :: libclawd-process
 * pty.c - Pseudo-terminal management
 *
 * Uses openpty()/forkpty() for PTY allocation and TIOCSWINSZ for resize.
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/pty.h>
#include <clawd/log.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/wait.h>

/*
 * The openpty/forkpty header lives in different places depending on
 * the platform.
 */
#ifdef __linux__
#include <pty.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
      defined(__OpenBSD__)
#include <util.h>
#endif

/* ---- public API --------------------------------------------------------- */

int clawd_pty_open(clawd_pty_t *pty)
{
    if (!pty)
        return -1;

    memset(pty, 0, sizeof(*pty));
    pty->master_fd = -1;
    pty->slave_fd  = -1;

    int master, slave;
    char name[256];

    if (openpty(&master, &slave, name, NULL, NULL) < 0) {
        CLAWD_ERROR("openpty failed: %s", strerror(errno));
        return -1;
    }

    pty->master_fd = master;
    pty->slave_fd  = slave;
    strncpy(pty->slave_name, name, sizeof(pty->slave_name) - 1);
    pty->slave_name[sizeof(pty->slave_name) - 1] = '\0';

    /* Save the original terminal attributes from the slave */
    if (tcgetattr(slave, &pty->orig_termios) < 0) {
        /* Non-fatal: the PTY might not have meaningful defaults yet */
        CLAWD_DEBUG("tcgetattr on slave: %s", strerror(errno));
    }

    /* Mark master close-on-exec so children don't inherit it accidentally */
    int flags = fcntl(master, F_GETFD, 0);
    if (flags >= 0)
        fcntl(master, F_SETFD, flags | FD_CLOEXEC);

    CLAWD_TRACE("pty opened: master=%d slave=%d name=%s",
                master, slave, pty->slave_name);
    return 0;
}

pid_t clawd_pty_fork(clawd_pty_t *pty, const char *cmd, char *const argv[])
{
    if (!pty || !cmd)
        return (pid_t)-1;

    /*
     * If the pty hasn't been opened yet, open it now.
     */
    if (pty->master_fd < 0 && clawd_pty_open(pty) < 0)
        return (pid_t)-1;

    pid_t pid = fork();
    if (pid < 0) {
        CLAWD_ERROR("fork failed: %s", strerror(errno));
        return (pid_t)-1;
    }

    if (pid == 0) {
        /* ---------- child ---------- */

        /* Close the master side -- we only use slave in the child */
        close(pty->master_fd);

        /* Create a new session so this child can get a controlling terminal */
        if (setsid() < 0)
            _exit(127);

        /* Set the slave as the controlling terminal */
#ifdef TIOCSCTTY
        if (ioctl(pty->slave_fd, TIOCSCTTY, 0) < 0) {
            /* Some kernels require a non-zero argument */
            (void)ioctl(pty->slave_fd, TIOCSCTTY, 1);
        }
#endif

        /* Wire stdin/stdout/stderr to the slave PTY */
        dup2(pty->slave_fd, STDIN_FILENO);
        dup2(pty->slave_fd, STDOUT_FILENO);
        dup2(pty->slave_fd, STDERR_FILENO);

        if (pty->slave_fd > STDERR_FILENO)
            close(pty->slave_fd);

        /* Exec the command */
        execvp(cmd, argv);
        _exit(127);  /* exec failed */
    }

    /* ---------- parent ---------- */

    /* Close the slave side in the parent */
    close(pty->slave_fd);
    pty->slave_fd = -1;
    pty->pid = pid;

    CLAWD_TRACE("pty_fork: child pid=%d cmd=%s", (int)pid, cmd);
    return pid;
}

ssize_t clawd_pty_read(clawd_pty_t *pty, void *buf, size_t len)
{
    if (!pty || pty->master_fd < 0 || !buf || len == 0)
        return -1;

    ssize_t n;
    do {
        n = read(pty->master_fd, buf, len);
    } while (n < 0 && errno == EINTR);

    return n;
}

ssize_t clawd_pty_write(clawd_pty_t *pty, const void *buf, size_t len)
{
    if (!pty || pty->master_fd < 0 || !buf || len == 0)
        return -1;

    const char *p = (const char *)buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t w = write(pty->master_fd, p, remaining);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += w;
        remaining -= (size_t)w;
    }

    return (ssize_t)len;
}

int clawd_pty_resize(clawd_pty_t *pty, int rows, int cols)
{
    if (!pty || pty->master_fd < 0)
        return -1;

    struct winsize ws = {
        .ws_row    = (unsigned short)rows,
        .ws_col    = (unsigned short)cols,
        .ws_xpixel = 0,
        .ws_ypixel = 0
    };

    if (ioctl(pty->master_fd, TIOCSWINSZ, &ws) < 0) {
        CLAWD_ERROR("TIOCSWINSZ failed: %s", strerror(errno));
        return -1;
    }

    /* Notify the child about the size change */
    if (pty->pid > 0)
        kill(pty->pid, SIGWINCH);

    CLAWD_TRACE("pty resize: rows=%d cols=%d", rows, cols);
    return 0;
}

void clawd_pty_close(clawd_pty_t *pty)
{
    if (!pty)
        return;

    if (pty->master_fd >= 0) {
        close(pty->master_fd);
        pty->master_fd = -1;
    }
    if (pty->slave_fd >= 0) {
        close(pty->slave_fd);
        pty->slave_fd = -1;
    }

    pty->pid = 0;
    pty->slave_name[0] = '\0';
}
