/*
 * kelp_internal.h — Internal prototypes shared between kernel sub-modules
 *
 * This eliminates -Wmissing-prototypes warnings for cross-file functions.
 */
#ifndef _KELP_INTERNAL_H
#define _KELP_INTERNAL_H

#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/atomic.h>

#include "../include/kelp/kelp_kernel.h"

/* Ring buffer message (shared struct) */
struct ring_msg {
    char   *data;
    size_t  len;
};

/* kelp_mod.c — global state accessors */
struct kelp_kstats *kelp_get_stats(void);
int kelp_get_log_level(void);
int kelp_get_netfilter_enabled(void);
ktime_t kelp_get_start_time(void);
atomic_t *kelp_get_open_count(void);
struct mutex *kelp_get_mutex(void);
struct ring_msg *kelp_get_ring(void);
int *kelp_get_ring_head(void);
int *kelp_get_ring_tail(void);
spinlock_t *kelp_get_ring_lock(void);
wait_queue_head_t *kelp_get_read_queue(void);
wait_queue_head_t *kelp_get_write_queue(void);

/* kelp_chardev.c */
int kelp_chardev_open(struct inode *inode, struct file *file);
int kelp_chardev_release(struct inode *inode, struct file *file);
ssize_t kelp_chardev_read(struct file *file, char __user *buf,
                            size_t count, loff_t *ppos);
ssize_t kelp_chardev_write(struct file *file, const char __user *buf,
                              size_t count, loff_t *ppos);
long kelp_chardev_ioctl(struct file *file, unsigned int cmd,
                          unsigned long arg);

/* kelp_procfs.c */
int kelp_procfs_init(void);
void kelp_procfs_exit(void);

/* kelp_netfilter.c */
int kelp_netfilter_init(void);
void kelp_netfilter_exit(void);
int kelp_nf_get_recent(char *buf, size_t buf_size);

/* kelp_procfs.c — proc_dir accessor for AI subsystem registration */
struct proc_dir_entry *kelp_procfs_get_dir(void);

/* kelp_ai_sched.c — AI inference scheduler */
int kelp_ai_sched_init(struct proc_dir_entry *proc_dir);
void kelp_ai_sched_exit(void);
int kelp_ai_sched_submit(unsigned long arg);
int kelp_ai_sched_poll(unsigned long arg);
uint32_t kelp_ai_sched_get_depth(void);
uint32_t kelp_ai_sched_get_total_submitted(void);
uint32_t kelp_ai_sched_get_total_completed(void);

/* kelp_semfs.c — Semantic FS events */
int kelp_semfs_init(struct proc_dir_entry *proc_dir);
void kelp_semfs_exit(void);
int kelp_semfs_get_events(unsigned long arg);
int kelp_semfs_watch(unsigned long arg);
uint64_t kelp_semfs_get_total_events(void);
uint32_t kelp_semfs_get_active_watches(void);
uint32_t kelp_semfs_get_buffer_used(void);

/* kelp_accel.c — Accelerator management */
int kelp_accel_init(struct proc_dir_entry *proc_dir);
void kelp_accel_exit(void);
int kelp_accel_list(unsigned long arg);
int kelp_accel_reserve(unsigned long arg);
uint32_t kelp_accel_get_count(void);

#endif /* _KELP_INTERNAL_H */
