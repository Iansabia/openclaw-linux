/*
 * clawd_kernel.h — Shared kernel/userspace ioctl definitions
 *
 * This header is used by both the kernel module and userspace tools.
 */
#ifndef _CLAWD_KMOD_H
#define _CLAWD_KMOD_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <sys/ioctl.h>
#include <stdint.h>
#endif

#define CLAWD_DEVICE_NAME  "clawd"
#define CLAWD_CLASS_NAME   "clawd"
#define CLAWD_PROC_NAME    "clawd"

/* ioctl magic number */
#define CLAWD_IOC_MAGIC  'C'

/* ioctl commands */
#define CLAWD_IOC_GET_VERSION    _IOR(CLAWD_IOC_MAGIC, 0, struct clawd_kversion)
#define CLAWD_IOC_GET_STATS      _IOR(CLAWD_IOC_MAGIC, 1, struct clawd_kstats)
#define CLAWD_IOC_SET_LOG_LEVEL  _IOW(CLAWD_IOC_MAGIC, 2, int)
#define CLAWD_IOC_ENABLE_NF      _IOW(CLAWD_IOC_MAGIC, 3, int)
#define CLAWD_IOC_QUERY_STATUS   _IOR(CLAWD_IOC_MAGIC, 4, struct clawd_kstatus)

#define CLAWD_IOC_MAXNR  4

/* Shared structures */
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

/* Maximum message size through /dev/clawd */
#define CLAWD_MAX_MSG_SIZE  (64 * 1024)

/* Netfilter action codes */
#define CLAWD_NF_LOG_ONLY   0
#define CLAWD_NF_ANALYZE    1

#endif /* _CLAWD_KMOD_H */
