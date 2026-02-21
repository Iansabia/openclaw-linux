/*
 * kelp-linux :: libkelp-process
 * pty.h - Pseudo-terminal management
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_PTY_H
#define KELP_PTY_H

#include <sys/types.h>
#include <termios.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * PTY handle.
 *
 * After kelp_pty_fork() the master side is used by the caller and
 * the slave side is connected to the child's stdin/stdout/stderr.
 */
typedef struct kelp_pty {
    int            master_fd;
    int            slave_fd;
    pid_t          pid;
    char           slave_name[256];
    struct termios orig_termios;
} kelp_pty_t;

/**
 * Open a new master/slave PTY pair (no fork).
 *
 * On success `pty->master_fd` and `pty->slave_fd` are set and
 * `pty->slave_name` holds the path of the slave device.
 * Returns 0 on success, -1 on failure.
 */
int kelp_pty_open(kelp_pty_t *pty);

/**
 * Fork a child process connected to a PTY.
 *
 * In the child: setsid(), slave becomes controlling terminal, exec(cmd, argv).
 * In the parent: slave is closed, master_fd is ready for I/O.
 *
 * Returns child PID in the parent, or (pid_t)-1 on failure.
 */
pid_t kelp_pty_fork(kelp_pty_t *pty, const char *cmd, char *const argv[]);

/**
 * Read from the PTY master side.
 *
 * Returns the number of bytes read, 0 on EOF, -1 on error.
 */
ssize_t kelp_pty_read(kelp_pty_t *pty, void *buf, size_t len);

/**
 * Write to the PTY master side.
 *
 * Returns the number of bytes written, or -1 on error.
 */
ssize_t kelp_pty_write(kelp_pty_t *pty, const void *buf, size_t len);

/**
 * Resize the PTY window (TIOCSWINSZ).
 *
 * Returns 0 on success, -1 on failure.
 */
int kelp_pty_resize(kelp_pty_t *pty, int rows, int cols);

/**
 * Close the PTY file descriptors and zero the structure.
 *
 * Does NOT kill or wait for the child -- the caller must manage the child
 * process lifetime separately.
 */
void kelp_pty_close(kelp_pty_t *pty);

#ifdef __cplusplus
}
#endif

#endif /* KELP_PTY_H */
