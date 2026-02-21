/*
 * clawd/kernel.h — Userspace API for the Clawd kernel module (/dev/clawd)
 *
 * This library wraps open/read/write/ioctl calls to the /dev/clawd
 * character device provided by the clawd.ko kernel module.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef CLAWD_KERNEL_H
#define CLAWD_KERNEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Device path -------------------------------------------------------- */

#define CLAWD_DEVICE_PATH  "/dev/clawd"
#define CLAWD_PROC_STATS   "/proc/clawd/stats"
#define CLAWD_PROC_NF      "/proc/clawd/netfilter"

/* ---- ioctl definitions (must match kernel/clawd_kernel.h) --------------- */

#define CLAWD_IOC_MAGIC  'C'

struct clawd_kversion {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
    char     build[64];
};

struct clawd_kstats {
    uint64_t messages_processed;
    uint64_t bytes_read;
    uint64_t bytes_written;
    uint64_t active_sessions;
    uint64_t netfilter_packets;
    uint64_t netfilter_blocked;
    uint64_t uptime_seconds;
};

struct clawd_kstatus {
    int      netfilter_enabled;
    int      log_level;
    int      chardev_open_count;
    uint64_t start_time;
};

#define CLAWD_IOC_GET_VERSION    _IOR(CLAWD_IOC_MAGIC, 0, struct clawd_kversion)
#define CLAWD_IOC_GET_STATS      _IOR(CLAWD_IOC_MAGIC, 1, struct clawd_kstats)
#define CLAWD_IOC_SET_LOG_LEVEL  _IOW(CLAWD_IOC_MAGIC, 2, int)
#define CLAWD_IOC_ENABLE_NF      _IOW(CLAWD_IOC_MAGIC, 3, int)
#define CLAWD_IOC_QUERY_STATUS   _IOR(CLAWD_IOC_MAGIC, 4, struct clawd_kstatus)

/* ---- Userspace API ------------------------------------------------------ */

/**
 * Open /dev/clawd.
 * Returns a file descriptor on success, -1 on error (errno set).
 */
int clawd_kernel_open(void);

/**
 * Close a previously opened /dev/clawd fd.
 * Returns 0 on success, -1 on error.
 */
int clawd_kernel_close(int fd);

/**
 * Send a message through /dev/clawd.
 * Returns 0 on success, -1 on error.
 */
int clawd_kernel_send(int fd, const char *msg, size_t len);

/**
 * Receive a message from /dev/clawd.
 * Returns a malloc'd buffer on success (caller must free), NULL on error.
 * If len is non-NULL, it receives the message length.
 */
char *clawd_kernel_recv(int fd, size_t *len);

/**
 * Query kernel module statistics via ioctl.
 * Returns 0 on success, -1 on error.
 */
int clawd_kernel_get_stats(int fd, struct clawd_kstats *stats);

/**
 * Query kernel module version via ioctl.
 * Returns 0 on success, -1 on error.
 */
int clawd_kernel_get_version(int fd, struct clawd_kversion *ver);

/**
 * Query kernel module status via ioctl.
 * Returns 0 on success, -1 on error.
 */
int clawd_kernel_get_status(int fd, struct clawd_kstatus *status);

/**
 * Check if the clawd kernel module is loaded and /dev/clawd is available.
 * Returns true if the device exists and can be opened.
 */
bool clawd_kernel_available(void);

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_KERNEL_H */
