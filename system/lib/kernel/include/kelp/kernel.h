/*
 * kelp/kernel.h — Userspace API for the Kelp kernel module (/dev/kelp)
 *
 * This library wraps open/read/write/ioctl calls to the /dev/kelp
 * character device provided by the kelp.ko kernel module.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef KELP_KERNEL_H
#define KELP_KERNEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Device path -------------------------------------------------------- */

#define KELP_DEVICE_PATH  "/dev/kelp"
#define KELP_PROC_STATS   "/proc/kelp/stats"
#define KELP_PROC_NF      "/proc/kelp/netfilter"
#define KELP_PROC_SCHED   "/proc/kelp/scheduler"
#define KELP_PROC_SEMFS   "/proc/kelp/semfs"
#define KELP_PROC_ACCEL   "/proc/kelp/accelerators"

/* ---- ioctl definitions (must match kernel/kelp_kernel.h) --------------- */

#define KELP_IOC_MAGIC  'K'

struct kelp_kversion {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
    char     build[64];
};

struct kelp_kstats {
    uint64_t messages_processed;
    uint64_t bytes_read;
    uint64_t bytes_written;
    uint64_t active_sessions;
    uint64_t netfilter_packets;
    uint64_t netfilter_blocked;
    uint64_t uptime_seconds;
};

struct kelp_kstatus {
    int      netfilter_enabled;
    int      log_level;
    int      chardev_open_count;
    uint64_t start_time;
};

#define KELP_IOC_GET_VERSION    _IOR(KELP_IOC_MAGIC, 0, struct kelp_kversion)
#define KELP_IOC_GET_STATS      _IOR(KELP_IOC_MAGIC, 1, struct kelp_kstats)
#define KELP_IOC_SET_LOG_LEVEL  _IOW(KELP_IOC_MAGIC, 2, int)
#define KELP_IOC_ENABLE_NF      _IOW(KELP_IOC_MAGIC, 3, int)
#define KELP_IOC_QUERY_STATUS   _IOR(KELP_IOC_MAGIC, 4, struct kelp_kstatus)

/* ---- AI Primitive structures -------------------------------------------- */

#define KELP_INFER_MODEL_HINT_LEN  64
#define KELP_INFER_FLAG_URGENT     (1 << 0)
#define KELP_INFER_FLAG_BATCH      (1 << 1)
#define KELP_INFER_FLAG_STREAM     (1 << 2)

struct kelp_infer_task {
    uint64_t task_id;
    int32_t  priority;
    uint32_t est_tokens;
    char     model_hint[KELP_INFER_MODEL_HINT_LEN];
    uint64_t submit_time_ns;
    uint32_t flags;
    uint32_t _reserved;
};

#define KELP_SEMFS_PATH_MAX     256
#define KELP_SEMFS_CREATE       1
#define KELP_SEMFS_MODIFY       2
#define KELP_SEMFS_DELETE       3
#define KELP_SEMFS_RENAME       4
#define KELP_SEMFS_BATCH_MAX    32
#define KELP_SEMFS_WATCH_ADD    1
#define KELP_SEMFS_WATCH_REMOVE 2

struct kelp_fs_event {
    uint64_t event_id;
    uint32_t type;
    uint32_t uid;
    uint64_t timestamp_ns;
    char     path[KELP_SEMFS_PATH_MAX];
};

struct kelp_semfs_batch {
    uint32_t count;
    uint32_t _reserved;
    struct kelp_fs_event events[KELP_SEMFS_BATCH_MAX];
};

struct kelp_semfs_watch {
    uint32_t action;
    uint32_t _reserved;
    char     path[KELP_SEMFS_PATH_MAX];
};

struct kelp_ai_status {
    int      netfilter_enabled;
    int      log_level;
    int      chardev_open_count;
    uint64_t start_time;
    uint32_t sched_queue_depth;
    uint32_t sched_total_submitted;
    uint32_t sched_total_completed;
    uint32_t _sched_reserved;
    uint64_t semfs_total_events;
    uint32_t semfs_active_watches;
    uint32_t semfs_buffer_used;
    uint32_t accel_count;
    uint32_t _accel_reserved;
};

/* AI ioctl commands */
#define KELP_IOC_SUBMIT_INFER   _IOW(KELP_IOC_MAGIC, 5, struct kelp_infer_task)
#define KELP_IOC_POLL_INFER     _IOR(KELP_IOC_MAGIC, 6, struct kelp_infer_task)
#define KELP_IOC_SEMFS_EVENTS   _IOWR(KELP_IOC_MAGIC, 7, struct kelp_semfs_batch)
#define KELP_IOC_SEMFS_WATCH    _IOW(KELP_IOC_MAGIC, 8, struct kelp_semfs_watch)
#define KELP_IOC_ACCEL_LIST     _IOR(KELP_IOC_MAGIC, 9, struct kelp_ai_status)
#define KELP_IOC_ACCEL_RESERVE  _IOW(KELP_IOC_MAGIC, 10, struct kelp_ai_status)
#define KELP_IOC_AI_STATUS      _IOR(KELP_IOC_MAGIC, 11, struct kelp_ai_status)

/* ---- Userspace API ------------------------------------------------------ */

/**
 * Open /dev/kelp.
 * Returns a file descriptor on success, -1 on error (errno set).
 */
int kelp_kernel_open(void);

/**
 * Close a previously opened /dev/kelp fd.
 * Returns 0 on success, -1 on error.
 */
int kelp_kernel_close(int fd);

/**
 * Send a message through /dev/kelp.
 * Returns 0 on success, -1 on error.
 */
int kelp_kernel_send(int fd, const char *msg, size_t len);

/**
 * Receive a message from /dev/kelp.
 * Returns a malloc'd buffer on success (caller must free), NULL on error.
 * If len is non-NULL, it receives the message length.
 */
char *kelp_kernel_recv(int fd, size_t *len);

/**
 * Query kernel module statistics via ioctl.
 * Returns 0 on success, -1 on error.
 */
int kelp_kernel_get_stats(int fd, struct kelp_kstats *stats);

/**
 * Query kernel module version via ioctl.
 * Returns 0 on success, -1 on error.
 */
int kelp_kernel_get_version(int fd, struct kelp_kversion *ver);

/**
 * Query kernel module status via ioctl.
 * Returns 0 on success, -1 on error.
 */
int kelp_kernel_get_status(int fd, struct kelp_kstatus *status);

/**
 * Check if the kelp kernel module is loaded and /dev/kelp is available.
 * Returns true if the device exists and can be opened.
 */
bool kelp_kernel_available(void);

/* ---- AI Primitive API --------------------------------------------------- */

/**
 * Submit an inference task to the kernel scheduler.
 * task->task_id and task->submit_time_ns are filled by the kernel.
 * Returns 0 on success, -1 on error.
 */
int kelp_kernel_submit_infer(int fd, struct kelp_infer_task *task);

/**
 * Poll (dequeue) the next highest-priority inference task.
 * Returns 0 on success, -1 on error (EAGAIN if queue is empty).
 */
int kelp_kernel_poll_infer(int fd, struct kelp_infer_task *task);

/**
 * Batch-read recent semantic FS events.
 * Set batch->count to max events desired; on return it holds actual count.
 * Returns 0 on success, -1 on error.
 */
int kelp_kernel_get_semfs_events(int fd, struct kelp_semfs_batch *batch);

/**
 * Add or remove a semantic FS watch path.
 * Returns 0 on success, -1 on error.
 */
int kelp_kernel_semfs_watch(int fd, struct kelp_semfs_watch *watch);

/**
 * Get unified AI status from the kernel module.
 * Returns 0 on success, -1 on error.
 */
int kelp_kernel_get_ai_status(int fd, struct kelp_ai_status *status);

#ifdef __cplusplus
}
#endif

#endif /* KELP_KERNEL_H */
