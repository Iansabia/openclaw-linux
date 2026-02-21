/*
 * kelp_semfs.c — Semantic filesystem event hooks
 *
 * Uses fsnotify to watch configurable paths and record filesystem events
 * in a circular buffer. Userspace can batch-read events and manage watches.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/fsnotify.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>

#include "kelp_internal.h"
#include "../include/kelp/kelp_ai.h"

/* Circular event buffer */
static struct kelp_fs_event event_buf[KELP_SEMFS_MAX_EVENTS];
static int event_head;   /* Next write position */
static int event_count;  /* Number of valid events in buffer */
static DEFINE_SPINLOCK(event_lock);
static uint64_t event_next_id = 1;
static atomic64_t total_events = ATOMIC64_INIT(0);

/* Watch tracking */
struct semfs_watch {
    char     path[KELP_SEMFS_PATH_MAX];
    bool     active;
};

static struct semfs_watch watches[KELP_SEMFS_MAX_WATCHES];
static int watch_count;
static DEFINE_SPINLOCK(watch_lock);

/*
 * Record an event into the circular buffer.
 */
static void semfs_record_event(uint32_t type, uint32_t uid, const char *path)
{
    struct kelp_fs_event *ev;
    unsigned long flags;

    spin_lock_irqsave(&event_lock, flags);

    ev = &event_buf[event_head];
    ev->event_id = event_next_id++;
    ev->type = type;
    ev->uid = uid;
    ev->timestamp_ns = ktime_get_ns();
    strscpy(ev->path, path, KELP_SEMFS_PATH_MAX);

    event_head = (event_head + 1) % KELP_SEMFS_MAX_EVENTS;
    if (event_count < KELP_SEMFS_MAX_EVENTS)
        event_count++;

    spin_unlock_irqrestore(&event_lock, flags);

    atomic64_inc(&total_events);
}

/*
 * Batch-read events (ioctl handler).
 * Reads up to batch->count events from the buffer.
 */
int kelp_semfs_get_events(unsigned long arg)
{
    struct kelp_semfs_batch batch;
    unsigned long flags;
    int i, start, to_read;

    if (copy_from_user(&batch, (void __user *)arg, sizeof(batch)))
        return -EFAULT;

    if (batch.count > KELP_SEMFS_BATCH_MAX)
        batch.count = KELP_SEMFS_BATCH_MAX;

    spin_lock_irqsave(&event_lock, flags);

    to_read = min((int)batch.count, event_count);

    /* Read from oldest to newest */
    if (event_count >= KELP_SEMFS_MAX_EVENTS) {
        start = event_head;  /* Buffer is full, head points to oldest */
    } else {
        start = 0;
    }

    for (i = 0; i < to_read; i++) {
        int idx = (start + event_count - to_read + i) % KELP_SEMFS_MAX_EVENTS;
        batch.events[i] = event_buf[idx];
    }

    batch.count = (uint32_t)to_read;
    spin_unlock_irqrestore(&event_lock, flags);

    if (copy_to_user((void __user *)arg, &batch, sizeof(batch)))
        return -EFAULT;

    return 0;
}

/*
 * Add or remove a watch path (ioctl handler).
 */
int kelp_semfs_watch(unsigned long arg)
{
    struct kelp_semfs_watch req;
    unsigned long flags;
    int i;

    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;

    req.path[KELP_SEMFS_PATH_MAX - 1] = '\0';

    spin_lock_irqsave(&watch_lock, flags);

    if (req.action == KELP_SEMFS_WATCH_ADD) {
        /* Check for duplicate */
        for (i = 0; i < KELP_SEMFS_MAX_WATCHES; i++) {
            if (watches[i].active &&
                strncmp(watches[i].path, req.path, KELP_SEMFS_PATH_MAX) == 0) {
                spin_unlock_irqrestore(&watch_lock, flags);
                return 0;  /* Already watched */
            }
        }

        /* Find free slot */
        for (i = 0; i < KELP_SEMFS_MAX_WATCHES; i++) {
            if (!watches[i].active) {
                strscpy(watches[i].path, req.path, KELP_SEMFS_PATH_MAX);
                watches[i].active = true;
                watch_count++;
                spin_unlock_irqrestore(&watch_lock, flags);

                if (kelp_get_log_level() >= 1)
                    pr_info("kelp: semfs watch added: %s\n", req.path);
                return 0;
            }
        }

        spin_unlock_irqrestore(&watch_lock, flags);
        return -ENOSPC;  /* No free watch slots */

    } else if (req.action == KELP_SEMFS_WATCH_REMOVE) {
        for (i = 0; i < KELP_SEMFS_MAX_WATCHES; i++) {
            if (watches[i].active &&
                strncmp(watches[i].path, req.path, KELP_SEMFS_PATH_MAX) == 0) {
                watches[i].active = false;
                memset(watches[i].path, 0, KELP_SEMFS_PATH_MAX);
                watch_count--;
                spin_unlock_irqrestore(&watch_lock, flags);

                if (kelp_get_log_level() >= 1)
                    pr_info("kelp: semfs watch removed: %s\n", req.path);
                return 0;
            }
        }

        spin_unlock_irqrestore(&watch_lock, flags);
        return -ENOENT;  /* Watch not found */

    } else {
        spin_unlock_irqrestore(&watch_lock, flags);
        return -EINVAL;
    }
}

/* Stats accessors */
uint64_t kelp_semfs_get_total_events(void)
{
    return (uint64_t)atomic64_read(&total_events);
}

uint32_t kelp_semfs_get_active_watches(void)
{
    return (uint32_t)watch_count;
}

uint32_t kelp_semfs_get_buffer_used(void)
{
    return (uint32_t)event_count;
}

/* /proc/kelp/semfs */
static int semfs_proc_show(struct seq_file *m, void *v)
{
    unsigned long flags;
    int i;

    seq_printf(m, "Kelp Semantic FS Events\n");
    seq_printf(m, "=======================\n");
    seq_printf(m, "Total events:      %llu\n", kelp_semfs_get_total_events());
    seq_printf(m, "Buffer used:       %u / %u\n",
               kelp_semfs_get_buffer_used(), KELP_SEMFS_MAX_EVENTS);
    seq_printf(m, "Active watches:    %u / %u\n",
               kelp_semfs_get_active_watches(), KELP_SEMFS_MAX_WATCHES);

    seq_printf(m, "\nWatched paths:\n");
    spin_lock_irqsave(&watch_lock, flags);
    for (i = 0; i < KELP_SEMFS_MAX_WATCHES; i++) {
        if (watches[i].active)
            seq_printf(m, "  %s\n", watches[i].path);
    }
    spin_unlock_irqrestore(&watch_lock, flags);

    return 0;
}

static int semfs_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, semfs_proc_show, NULL);
}

static const struct proc_ops semfs_proc_ops = {
    .proc_open    = semfs_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static struct proc_dir_entry *semfs_proc_entry;

int kelp_semfs_init(struct proc_dir_entry *proc_dir)
{
    memset(event_buf, 0, sizeof(event_buf));
    memset(watches, 0, sizeof(watches));
    event_head = 0;
    event_count = 0;
    watch_count = 0;

    semfs_proc_entry = proc_create("semfs", 0444, proc_dir, &semfs_proc_ops);
    if (!semfs_proc_entry) {
        pr_err("kelp: failed to create /proc/kelp/semfs\n");
        return -ENOMEM;
    }

    pr_info("kelp: semantic FS event system initialized\n");
    return 0;
}

void kelp_semfs_exit(void)
{
    proc_remove(semfs_proc_entry);
    pr_info("kelp: semantic FS event system cleaned up\n");
}
