/*
 * clawd_internal.h — Internal prototypes shared between kernel sub-modules
 *
 * This eliminates -Wmissing-prototypes warnings for cross-file functions.
 */
#ifndef _CLAWD_INTERNAL_H
#define _CLAWD_INTERNAL_H

#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/atomic.h>

#include "clawd_kernel.h"

/* Ring buffer message (shared struct) */
struct ring_msg {
    char   *data;
    size_t  len;
};

/* clawd_mod.c — global state accessors */
struct clawd_kstats *clawd_get_stats(void);
int clawd_get_log_level(void);
int clawd_get_netfilter_enabled(void);
ktime_t clawd_get_start_time(void);
atomic_t *clawd_get_open_count(void);
struct mutex *clawd_get_mutex(void);
struct ring_msg *clawd_get_ring(void);
int *clawd_get_ring_head(void);
int *clawd_get_ring_tail(void);
spinlock_t *clawd_get_ring_lock(void);
wait_queue_head_t *clawd_get_read_queue(void);
wait_queue_head_t *clawd_get_write_queue(void);

/* clawd_chardev.c */
int clawd_chardev_open(struct inode *inode, struct file *file);
int clawd_chardev_release(struct inode *inode, struct file *file);
ssize_t clawd_chardev_read(struct file *file, char __user *buf,
                            size_t count, loff_t *ppos);
ssize_t clawd_chardev_write(struct file *file, const char __user *buf,
                              size_t count, loff_t *ppos);
long clawd_chardev_ioctl(struct file *file, unsigned int cmd,
                          unsigned long arg);

/* clawd_procfs.c */
int clawd_procfs_init(void);
void clawd_procfs_exit(void);

/* clawd_netfilter.c */
int clawd_netfilter_init(void);
void clawd_netfilter_exit(void);
int clawd_nf_get_recent(char *buf, size_t buf_size);

#endif /* _CLAWD_INTERNAL_H */
