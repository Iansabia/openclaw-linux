/*
 * clawd_chardev.c — /dev/clawd character device implementation
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

#include "clawd_kernel.h"

/* Ring buffer parameters */
#define RING_SIZE 64
#define MSG_MAX_LEN CLAWD_MAX_MSG_SIZE

struct ring_msg {
    char   *data;
    size_t  len;
};

/* External accessors from clawd_mod.c */
extern struct clawd_kstats *clawd_get_stats(void);
extern int clawd_get_log_level(void);
extern int clawd_get_netfilter_enabled(void);
extern ktime_t clawd_get_start_time(void);
extern atomic_t *clawd_get_open_count(void);
extern struct mutex *clawd_get_mutex(void);

extern struct ring_msg *clawd_get_ring(void);
extern int *clawd_get_ring_head(void);
extern int *clawd_get_ring_tail(void);
extern spinlock_t *clawd_get_ring_lock(void);
extern wait_queue_head_t *clawd_get_read_queue(void);
extern wait_queue_head_t *clawd_get_write_queue(void);

/* Per-file private data */
struct clawd_file_data {
    char   *read_buf;     /* Pending read data */
    size_t  read_len;
    size_t  read_pos;
};

int clawd_chardev_open(struct inode *inode, struct file *file)
{
    struct clawd_file_data *fdata;

    fdata = kzalloc(sizeof(*fdata), GFP_KERNEL);
    if (!fdata)
        return -ENOMEM;

    file->private_data = fdata;
    atomic_inc(clawd_get_open_count());

    if (clawd_get_log_level() >= 2)
        pr_info("clawd: device opened (count=%d)\n",
                atomic_read(clawd_get_open_count()));

    return 0;
}

int clawd_chardev_release(struct inode *inode, struct file *file)
{
    struct clawd_file_data *fdata = file->private_data;

    if (fdata) {
        kfree(fdata->read_buf);
        kfree(fdata);
    }

    atomic_dec(clawd_get_open_count());

    if (clawd_get_log_level() >= 2)
        pr_info("clawd: device closed (count=%d)\n",
                atomic_read(clawd_get_open_count()));

    return 0;
}

/*
 * Read from /dev/clawd — returns the next message from the ring buffer.
 * Blocks until data is available.
 */
ssize_t clawd_chardev_read(struct file *file, char __user *buf,
                            size_t count, loff_t *ppos)
{
    struct clawd_file_data *fdata = file->private_data;
    struct ring_msg *ring = clawd_get_ring();
    int *tail = clawd_get_ring_tail();
    int *head = clawd_get_ring_head();
    spinlock_t *lock = clawd_get_ring_lock();
    wait_queue_head_t *rq = clawd_get_read_queue();
    struct clawd_kstats *st = clawd_get_stats();
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

    wake_up_interruptible(clawd_get_write_queue());

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
 * Write to /dev/clawd — enqueue a message in the ring buffer.
 * The gateway daemon reads from this to process requests.
 */
ssize_t clawd_chardev_write(struct file *file, const char __user *buf,
                              size_t count, loff_t *ppos)
{
    struct ring_msg *ring = clawd_get_ring();
    int *head = clawd_get_ring_head();
    int *tail = clawd_get_ring_tail();
    spinlock_t *lock = clawd_get_ring_lock();
    wait_queue_head_t *wq = clawd_get_write_queue();
    struct clawd_kstats *st = clawd_get_stats();
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

    wake_up_interruptible(clawd_get_read_queue());

    st->bytes_written += count;

    if (clawd_get_log_level() >= 2)
        pr_info("clawd: message written (%zu bytes)\n", count);

    return (ssize_t)count;
}

/*
 * ioctl handler for /dev/clawd
 */
long clawd_chardev_ioctl(struct file *file, unsigned int cmd,
                          unsigned long arg)
{
    struct clawd_kstats *st = clawd_get_stats();
    ktime_t now;
    s64 uptime_ns;

    if (_IOC_TYPE(cmd) != CLAWD_IOC_MAGIC)
        return -ENOTTY;
    if (_IOC_NR(cmd) > CLAWD_IOC_MAXNR)
        return -ENOTTY;

    switch (cmd) {
    case CLAWD_IOC_GET_VERSION: {
        struct clawd_kversion ver = {
            .major = 0,
            .minor = 1,
            .patch = 0,
        };
        snprintf(ver.build, sizeof(ver.build), "%s %s", __DATE__, __TIME__);
        if (copy_to_user((void __user *)arg, &ver, sizeof(ver)))
            return -EFAULT;
        return 0;
    }

    case CLAWD_IOC_GET_STATS: {
        now = ktime_get_boottime();
        uptime_ns = ktime_to_ns(ktime_sub(now, clawd_get_start_time()));
        st->uptime_seconds = (uint64_t)(uptime_ns / NSEC_PER_SEC);
        st->active_sessions = (uint64_t)atomic_read(clawd_get_open_count());

        if (copy_to_user((void __user *)arg, st, sizeof(*st)))
            return -EFAULT;
        return 0;
    }

    case CLAWD_IOC_SET_LOG_LEVEL: {
        int level;
        if (copy_from_user(&level, (void __user *)arg, sizeof(level)))
            return -EFAULT;
        if (level < 0 || level > 2)
            return -EINVAL;
        pr_info("clawd: log level set to %d\n", level);
        return 0;
    }

    case CLAWD_IOC_ENABLE_NF: {
        int enable;
        if (copy_from_user(&enable, (void __user *)arg, sizeof(enable)))
            return -EFAULT;
        pr_info("clawd: netfilter %s\n", enable ? "enabled" : "disabled");
        return 0;
    }

    case CLAWD_IOC_QUERY_STATUS: {
        struct clawd_kstatus status;
        now = ktime_get_boottime();

        status.netfilter_enabled = clawd_get_netfilter_enabled();
        status.log_level = clawd_get_log_level();
        status.chardev_open_count = atomic_read(clawd_get_open_count());
        status.start_time = (uint64_t)ktime_to_ns(clawd_get_start_time());

        if (copy_to_user((void __user *)arg, &status, sizeof(status)))
            return -EFAULT;
        return 0;
    }

    default:
        return -ENOTTY;
    }
}
