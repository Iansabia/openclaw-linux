/*
 * kelp_chardev.c — /dev/kelp character device implementation
 *
 * Provides read/write/ioctl interface for userspace <-> kernel IPC.
 * Write a prompt -> read back the response (forwarded via gateway).
 */

#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/ktime.h>

#include "kelp_internal.h"
#include "../include/kelp/kelp_ai.h"

/* Ring buffer parameters */
#define RING_SIZE 64
#define MSG_MAX_LEN KELP_MAX_MSG_SIZE

/* Per-file private data */
struct kelp_file_data {
    char   *read_buf;     /* Pending read data */
    size_t  read_len;
    size_t  read_pos;
};

int kelp_chardev_open(struct inode *inode, struct file *file)
{
    struct kelp_file_data *fdata;

    fdata = kzalloc(sizeof(*fdata), GFP_KERNEL);
    if (!fdata)
        return -ENOMEM;

    file->private_data = fdata;
    atomic_inc(kelp_get_open_count());

    if (kelp_get_log_level() >= 2)
        pr_info("kelp: device opened (count=%d)\n",
                atomic_read(kelp_get_open_count()));

    return 0;
}

int kelp_chardev_release(struct inode *inode, struct file *file)
{
    struct kelp_file_data *fdata = file->private_data;

    if (fdata) {
        kfree(fdata->read_buf);
        kfree(fdata);
    }

    atomic_dec(kelp_get_open_count());

    if (kelp_get_log_level() >= 2)
        pr_info("kelp: device closed (count=%d)\n",
                atomic_read(kelp_get_open_count()));

    return 0;
}

/*
 * Read from /dev/kelp — returns the next message from the ring buffer.
 * Blocks until data is available.
 */
ssize_t kelp_chardev_read(struct file *file, char __user *buf,
                            size_t count, loff_t *ppos)
{
    struct kelp_file_data *fdata = file->private_data;
    struct ring_msg *ring = kelp_get_ring();
    int *tail = kelp_get_ring_tail();
    int *head = kelp_get_ring_head();
    spinlock_t *lock = kelp_get_ring_lock();
    wait_queue_head_t *rq = kelp_get_read_queue();
    struct kelp_kstats *st = kelp_get_stats();
    ssize_t ret;
    unsigned long flags;

    /* If we have leftover data from a previous partial read */
    if (fdata->read_buf && fdata->read_pos < fdata->read_len) {
        size_t remaining = fdata->read_len - fdata->read_pos;
        size_t to_copy = min(count, remaining);

        if (copy_to_user(buf, fdata->read_buf + fdata->read_pos, to_copy))
            return -EFAULT;

        fdata->read_pos += to_copy;
        if (fdata->read_pos >= fdata->read_len) {
            kfree(fdata->read_buf);
            fdata->read_buf = NULL;
            fdata->read_len = 0;
            fdata->read_pos = 0;
        }

        st->bytes_read += to_copy;
        return (ssize_t)to_copy;
    }

    /* Wait for data in ring buffer */
    if (file->f_flags & O_NONBLOCK) {
        spin_lock_irqsave(lock, flags);
        if (*head == *tail) {
            spin_unlock_irqrestore(lock, flags);
            return -EAGAIN;
        }
        spin_unlock_irqrestore(lock, flags);
    } else {
        ret = wait_event_interruptible(*rq, *head != *tail);
        if (ret)
            return ret;
    }

    /* Dequeue message */
    spin_lock_irqsave(lock, flags);
    if (*head == *tail) {
        spin_unlock_irqrestore(lock, flags);
        return 0;
    }

    struct ring_msg *msg = &ring[*tail];
    char *data = msg->data;
    size_t data_len = msg->len;
    msg->data = NULL;
    msg->len = 0;
    *tail = (*tail + 1) % RING_SIZE;
    spin_unlock_irqrestore(lock, flags);

    wake_up_interruptible(kelp_get_write_queue());

    /* Copy to user */
    size_t to_copy = min(count, data_len);
    if (copy_to_user(buf, data, to_copy)) {
        kfree(data);
        return -EFAULT;
    }

    /* Save remainder for next read */
    if (to_copy < data_len) {
        fdata->read_buf = data;
        fdata->read_len = data_len;
        fdata->read_pos = to_copy;
    } else {
        kfree(data);
    }

    st->bytes_read += to_copy;
    st->messages_processed++;
    return (ssize_t)to_copy;
}

/*
 * Write to /dev/kelp — enqueue a message in the ring buffer.
 * The gateway daemon reads from this to process requests.
 */
ssize_t kelp_chardev_write(struct file *file, const char __user *buf,
                              size_t count, loff_t *ppos)
{
    struct ring_msg *ring = kelp_get_ring();
    int *head = kelp_get_ring_head();
    int *tail = kelp_get_ring_tail();
    spinlock_t *lock = kelp_get_ring_lock();
    wait_queue_head_t *wq = kelp_get_write_queue();
    struct kelp_kstats *st = kelp_get_stats();
    unsigned long flags;
    int next;
    char *data;

    if (count == 0)
        return 0;

    if (count > MSG_MAX_LEN)
        count = MSG_MAX_LEN;

    /* Allocate buffer for the message */
    data = kmalloc(count + 1, GFP_KERNEL);
    if (!data)
        return -ENOMEM;

    if (copy_from_user(data, buf, count)) {
        kfree(data);
        return -EFAULT;
    }
    data[count] = '\0';

    /* Enqueue in ring buffer */
    spin_lock_irqsave(lock, flags);
    next = (*head + 1) % RING_SIZE;

    if (next == *tail) {
        /* Ring full */
        spin_unlock_irqrestore(lock, flags);
        if (file->f_flags & O_NONBLOCK) {
            kfree(data);
            return -EAGAIN;
        }
        /* Wait for space */
        spin_unlock_irqrestore(lock, flags);
        if (wait_event_interruptible(*wq, ((*head + 1) % RING_SIZE) != *tail)) {
            kfree(data);
            return -ERESTARTSYS;
        }
        spin_lock_irqsave(lock, flags);
        next = (*head + 1) % RING_SIZE;
    }

    /* Free any old message at this slot */
    kfree(ring[*head].data);
    ring[*head].data = data;
    ring[*head].len = count;
    *head = next;
    spin_unlock_irqrestore(lock, flags);

    wake_up_interruptible(kelp_get_read_queue());

    st->bytes_written += count;

    if (kelp_get_log_level() >= 2)
        pr_info("kelp: message written (%zu bytes)\n", count);

    return (ssize_t)count;
}

/*
 * ioctl handler for /dev/kelp
 */
long kelp_chardev_ioctl(struct file *file, unsigned int cmd,
                          unsigned long arg)
{
    struct kelp_kstats *st = kelp_get_stats();
    ktime_t now;
    s64 uptime_ns;

    if (_IOC_TYPE(cmd) != KELP_IOC_MAGIC)
        return -ENOTTY;
    if (_IOC_NR(cmd) > KELP_IOC_AI_MAXNR)
        return -ENOTTY;

    switch (cmd) {
    case KELP_IOC_GET_VERSION: {
        struct kelp_kversion ver = {
            .major = 0,
            .minor = 1,
            .patch = 0,
        };
        strscpy(ver.build, "kelp 0.1.0", sizeof(ver.build));
        if (copy_to_user((void __user *)arg, &ver, sizeof(ver)))
            return -EFAULT;
        return 0;
    }

    case KELP_IOC_GET_STATS: {
        now = ktime_get_boottime();
        uptime_ns = ktime_to_ns(ktime_sub(now, kelp_get_start_time()));
        st->uptime_seconds = (uint64_t)(uptime_ns / NSEC_PER_SEC);
        st->active_sessions = (uint64_t)atomic_read(kelp_get_open_count());

        if (copy_to_user((void __user *)arg, st, sizeof(*st)))
            return -EFAULT;
        return 0;
    }

    case KELP_IOC_SET_LOG_LEVEL: {
        int level;
        if (copy_from_user(&level, (void __user *)arg, sizeof(level)))
            return -EFAULT;
        if (level < 0 || level > 2)
            return -EINVAL;
        pr_info("kelp: log level set to %d\n", level);
        return 0;
    }

    case KELP_IOC_ENABLE_NF: {
        int enable;
        if (copy_from_user(&enable, (void __user *)arg, sizeof(enable)))
            return -EFAULT;
        pr_info("kelp: netfilter %s\n", enable ? "enabled" : "disabled");
        return 0;
    }

    case KELP_IOC_QUERY_STATUS: {
        struct kelp_kstatus status;
        now = ktime_get_boottime();

        status.netfilter_enabled = kelp_get_netfilter_enabled();
        status.log_level = kelp_get_log_level();
        status.chardev_open_count = atomic_read(kelp_get_open_count());
        status.start_time = (uint64_t)ktime_to_ns(kelp_get_start_time());

        if (copy_to_user((void __user *)arg, &status, sizeof(status)))
            return -EFAULT;
        return 0;
    }

    /* AI Primitives — inference scheduler */
    case KELP_IOC_SUBMIT_INFER:
        return kelp_ai_sched_submit(arg);

    case KELP_IOC_POLL_INFER:
        return kelp_ai_sched_poll(arg);

    /* AI Primitives — semantic FS events */
    case KELP_IOC_SEMFS_EVENTS:
        return kelp_semfs_get_events(arg);

    case KELP_IOC_SEMFS_WATCH:
        return kelp_semfs_watch(arg);

    /* AI Primitives — accelerator management */
    case KELP_IOC_ACCEL_LIST:
        return kelp_accel_list(arg);

    case KELP_IOC_ACCEL_RESERVE:
        return kelp_accel_reserve(arg);

    /* AI Primitives — unified status */
    case KELP_IOC_AI_STATUS: {
        struct kelp_ai_status ai_status;
        now = ktime_get_boottime();

        memset(&ai_status, 0, sizeof(ai_status));

        /* Base status */
        ai_status.netfilter_enabled = kelp_get_netfilter_enabled();
        ai_status.log_level = kelp_get_log_level();
        ai_status.chardev_open_count = atomic_read(kelp_get_open_count());
        ai_status.start_time = (uint64_t)ktime_to_ns(kelp_get_start_time());

        /* Scheduler stats */
        ai_status.sched_queue_depth = kelp_ai_sched_get_depth();
        ai_status.sched_total_submitted = kelp_ai_sched_get_total_submitted();
        ai_status.sched_total_completed = kelp_ai_sched_get_total_completed();

        /* Semantic FS stats */
        ai_status.semfs_total_events = kelp_semfs_get_total_events();
        ai_status.semfs_active_watches = kelp_semfs_get_active_watches();
        ai_status.semfs_buffer_used = kelp_semfs_get_buffer_used();

        /* Accelerator stats */
        ai_status.accel_count = kelp_accel_get_count();

        if (copy_to_user((void __user *)arg, &ai_status, sizeof(ai_status)))
            return -EFAULT;
        return 0;
    }

    default:
        return -ENOTTY;
    }
}
