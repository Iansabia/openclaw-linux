/*
 * kelp_ai.h — AI primitive structures and ioctl definitions
 *
 * Shared between kernel module and userspace.
 * Defines inference scheduler, semantic FS events, and accelerator management.
 */
#ifndef _KELP_AI_H
#define _KELP_AI_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <sys/ioctl.h>
#include <stdint.h>
#endif

#include "kelp_kernel.h"

/* ========================================================================
 * Inference Scheduler
 * ======================================================================== */

#define KELP_INFER_MODEL_HINT_LEN  64
#define KELP_INFER_MAX_QUEUE       1024

/* Inference task flags */
#define KELP_INFER_FLAG_URGENT     (1 << 0)
#define KELP_INFER_FLAG_BATCH      (1 << 1)
#define KELP_INFER_FLAG_STREAM     (1 << 2)

struct kelp_infer_task {
    uint64_t task_id;
    int32_t  priority;          /* Higher = more urgent */
    uint32_t est_tokens;        /* Estimated token count */
    char     model_hint[KELP_INFER_MODEL_HINT_LEN];
    uint64_t submit_time_ns;    /* Filled by kernel on submit */
    uint32_t flags;
    uint32_t _reserved;
};

/* ioctls 5-6: inference scheduler */
#define KELP_IOC_SUBMIT_INFER   _IOW(KELP_IOC_MAGIC, 5, struct kelp_infer_task)
#define KELP_IOC_POLL_INFER     _IOR(KELP_IOC_MAGIC, 6, struct kelp_infer_task)

/* ========================================================================
 * Semantic FS Events
 * ======================================================================== */

#define KELP_SEMFS_PATH_MAX     256
#define KELP_SEMFS_MAX_EVENTS   256
#define KELP_SEMFS_MAX_WATCHES  64

/* Event types */
#define KELP_SEMFS_CREATE       1
#define KELP_SEMFS_MODIFY       2
#define KELP_SEMFS_DELETE       3
#define KELP_SEMFS_RENAME       4

struct kelp_fs_event {
    uint64_t event_id;
    uint32_t type;              /* KELP_SEMFS_CREATE, etc. */
    uint32_t uid;
    uint64_t timestamp_ns;
    char     path[KELP_SEMFS_PATH_MAX];
};

#define KELP_SEMFS_BATCH_MAX    32

struct kelp_semfs_batch {
    uint32_t count;             /* In: max events to read, Out: actual count */
    uint32_t _reserved;
    struct kelp_fs_event events[KELP_SEMFS_BATCH_MAX];
};

/* Watch action flags */
#define KELP_SEMFS_WATCH_ADD    1
#define KELP_SEMFS_WATCH_REMOVE 2

struct kelp_semfs_watch {
    uint32_t action;            /* ADD or REMOVE */
    uint32_t _reserved;
    char     path[KELP_SEMFS_PATH_MAX];
};

/* ioctls 7-8: semantic FS */
#define KELP_IOC_SEMFS_EVENTS   _IOWR(KELP_IOC_MAGIC, 7, struct kelp_semfs_batch)
#define KELP_IOC_SEMFS_WATCH    _IOW(KELP_IOC_MAGIC, 8, struct kelp_semfs_watch)

/* ========================================================================
 * Accelerator Management (stubs)
 * ======================================================================== */

#define KELP_ACCEL_NAME_LEN     64
#define KELP_ACCEL_MAX          16

/* Accelerator types */
#define KELP_ACCEL_CUDA         1
#define KELP_ACCEL_ROCM         2
#define KELP_ACCEL_NPU          3

struct kelp_accel_info {
    uint32_t id;
    uint32_t type;              /* KELP_ACCEL_CUDA, etc. */
    uint64_t memory_total;      /* bytes */
    uint64_t memory_free;       /* bytes */
    char     name[KELP_ACCEL_NAME_LEN];
};

struct kelp_accel_list {
    uint32_t count;             /* Out: number of accelerators */
    uint32_t _reserved;
    struct kelp_accel_info accels[KELP_ACCEL_MAX];
};

struct kelp_accel_reserve {
    uint32_t accel_id;
    uint32_t _reserved;
    uint64_t bytes;             /* Amount of memory to reserve */
};

/* ioctls 9-10: accelerator management */
#define KELP_IOC_ACCEL_LIST     _IOR(KELP_IOC_MAGIC, 9, struct kelp_accel_list)
#define KELP_IOC_ACCEL_RESERVE  _IOW(KELP_IOC_MAGIC, 10, struct kelp_accel_reserve)

/* ========================================================================
 * Unified AI Status
 * ======================================================================== */

struct kelp_ai_status {
    /* Existing fields */
    int      netfilter_enabled;
    int      log_level;
    int      chardev_open_count;
    uint64_t start_time;

    /* Scheduler */
    uint32_t sched_queue_depth;
    uint32_t sched_total_submitted;
    uint32_t sched_total_completed;
    uint32_t _sched_reserved;

    /* Semantic FS */
    uint64_t semfs_total_events;
    uint32_t semfs_active_watches;
    uint32_t semfs_buffer_used;

    /* Accelerators */
    uint32_t accel_count;
    uint32_t _accel_reserved;
};

/* ioctl 11: unified AI status */
#define KELP_IOC_AI_STATUS      _IOR(KELP_IOC_MAGIC, 11, struct kelp_ai_status)

/* Updated max ioctl number */
#define KELP_IOC_AI_MAXNR       11

#endif /* _KELP_AI_H */
