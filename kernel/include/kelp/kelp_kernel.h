/*
 * kelp_kernel.h — Shared kernel/userspace ioctl definitions
 *
 * This header is used by both the kernel module and userspace tools.
 */
#ifndef _KELP_KMOD_H
#define _KELP_KMOD_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <sys/ioctl.h>
#include <stdint.h>
#endif

#define KELP_DEVICE_NAME  "kelp"
#define KELP_CLASS_NAME   "kelp"
#define KELP_PROC_NAME    "kelp"

/* ioctl magic number */
#define KELP_IOC_MAGIC  'K'

/* ioctl commands */
#define KELP_IOC_GET_VERSION    _IOR(KELP_IOC_MAGIC, 0, struct kelp_kversion)
#define KELP_IOC_GET_STATS      _IOR(KELP_IOC_MAGIC, 1, struct kelp_kstats)
#define KELP_IOC_SET_LOG_LEVEL  _IOW(KELP_IOC_MAGIC, 2, int)
#define KELP_IOC_ENABLE_NF      _IOW(KELP_IOC_MAGIC, 3, int)
#define KELP_IOC_QUERY_STATUS   _IOR(KELP_IOC_MAGIC, 4, struct kelp_kstatus)

#define KELP_IOC_MAXNR  4

/* Shared structures */
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

/* Maximum message size through /dev/kelp */
#define KELP_MAX_MSG_SIZE  (64 * 1024)

/* Netfilter action codes */
#define KELP_NF_LOG_ONLY   0
#define KELP_NF_ANALYZE    1

#endif /* _KELP_KMOD_H */
