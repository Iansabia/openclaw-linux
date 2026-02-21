/*
 * kelp_ai_sched.c — AI inference scheduler
 *
 * Implements a kernel-space priority queue (rbtree) for scheduling
 * AI inference tasks. Userspace submits tasks with priorities;
 * the scheduler dequeues in priority order.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/atomic.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#include "kelp_internal.h"
#include "../include/kelp/kelp_ai.h"

/* Wrapper for rbtree node */
struct sched_node {
    struct rb_node  rb;
    struct kelp_infer_task task;
};

static struct rb_root       sched_tree = RB_ROOT;
static DEFINE_SPINLOCK(sched_lock);
static atomic_t             sched_depth = ATOMIC_INIT(0);
static atomic_t             sched_total_submitted = ATOMIC_INIT(0);
static atomic_t             sched_total_completed = ATOMIC_INIT(0);
static uint64_t             sched_next_id = 1;

/*
 * Insert a task into the rbtree, ordered by priority (descending)
 * then by submit time (ascending) for FIFO within same priority.
 */
static void sched_insert(struct sched_node *new_node)
{
    struct rb_node **link = &sched_tree.rb_node;
    struct rb_node *parent = NULL;
    struct sched_node *entry;

    while (*link) {
        parent = *link;
        entry = rb_entry(parent, struct sched_node, rb);

        /* Higher priority goes left (dequeued first) */
        if (new_node->task.priority > entry->task.priority) {
            link = &parent->rb_left;
        } else if (new_node->task.priority < entry->task.priority) {
            link = &parent->rb_right;
        } else {
            /* Same priority: earlier submit time goes left */
            if (new_node->task.submit_time_ns <= entry->task.submit_time_ns)
                link = &parent->rb_left;
            else
                link = &parent->rb_right;
        }
    }

    rb_link_node(&new_node->rb, parent, link);
    rb_insert_color(&new_node->rb, &sched_tree);
}

/*
 * Dequeue the highest-priority task (leftmost node).
 */
static struct sched_node *sched_dequeue(void)
{
    struct rb_node *node = rb_first(&sched_tree);
    struct sched_node *entry;

    if (!node)
        return NULL;

    entry = rb_entry(node, struct sched_node, rb);
    rb_erase(node, &sched_tree);
    return entry;
}

/*
 * Submit an inference task (ioctl handler).
 */
int kelp_ai_sched_submit(unsigned long arg)
{
    struct kelp_infer_task user_task;
    struct sched_node *node;
    unsigned long flags;

    if (copy_from_user(&user_task, (void __user *)arg, sizeof(user_task)))
        return -EFAULT;

    if (atomic_read(&sched_depth) >= KELP_INFER_MAX_QUEUE)
        return -ENOSPC;

    node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node)
        return -ENOMEM;

    node->task = user_task;
    node->task.submit_time_ns = ktime_get_ns();

    spin_lock_irqsave(&sched_lock, flags);
    node->task.task_id = sched_next_id++;
    sched_insert(node);
    spin_unlock_irqrestore(&sched_lock, flags);

    atomic_inc(&sched_depth);
    atomic_inc(&sched_total_submitted);

    /* Copy back with assigned task_id and submit_time */
    if (copy_to_user((void __user *)arg, &node->task, sizeof(node->task)))
        return -EFAULT;

    if (kelp_get_log_level() >= 2)
        pr_info("kelp: inference task %llu submitted (priority=%d)\n",
                node->task.task_id, node->task.priority);

    return 0;
}

/*
 * Poll (dequeue) the next highest-priority inference task.
 */
int kelp_ai_sched_poll(unsigned long arg)
{
    struct sched_node *node;
    unsigned long flags;

    spin_lock_irqsave(&sched_lock, flags);
    node = sched_dequeue();
    spin_unlock_irqrestore(&sched_lock, flags);

    if (!node)
        return -EAGAIN;

    if (copy_to_user((void __user *)arg, &node->task, sizeof(node->task))) {
        /* Re-insert on failure */
        spin_lock_irqsave(&sched_lock, flags);
        sched_insert(node);
        spin_unlock_irqrestore(&sched_lock, flags);
        return -EFAULT;
    }

    atomic_dec(&sched_depth);
    atomic_inc(&sched_total_completed);
    kfree(node);

    return 0;
}

/* Stats accessors for procfs / ai_status */
uint32_t kelp_ai_sched_get_depth(void)
{
    return (uint32_t)atomic_read(&sched_depth);
}

uint32_t kelp_ai_sched_get_total_submitted(void)
{
    return (uint32_t)atomic_read(&sched_total_submitted);
}

uint32_t kelp_ai_sched_get_total_completed(void)
{
    return (uint32_t)atomic_read(&sched_total_completed);
}

/* /proc/kelp/scheduler */
static int sched_proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "Kelp AI Inference Scheduler\n");
    seq_printf(m, "===========================\n");
    seq_printf(m, "Queue depth:       %u\n", kelp_ai_sched_get_depth());
    seq_printf(m, "Total submitted:   %u\n", kelp_ai_sched_get_total_submitted());
    seq_printf(m, "Total completed:   %u\n", kelp_ai_sched_get_total_completed());
    return 0;
}

static int sched_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, sched_proc_show, NULL);
}

static const struct proc_ops sched_proc_ops = {
    .proc_open    = sched_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static struct proc_dir_entry *sched_proc_entry;

int kelp_ai_sched_init(struct proc_dir_entry *proc_dir)
{
    sched_proc_entry = proc_create("scheduler", 0444, proc_dir, &sched_proc_ops);
    if (!sched_proc_entry) {
        pr_err("kelp: failed to create /proc/kelp/scheduler\n");
        return -ENOMEM;
    }

    pr_info("kelp: AI inference scheduler initialized\n");
    return 0;
}

void kelp_ai_sched_exit(void)
{
    struct sched_node *node;
    unsigned long flags;

    /* Drain the queue */
    spin_lock_irqsave(&sched_lock, flags);
    while ((node = sched_dequeue()) != NULL)
        kfree(node);
    spin_unlock_irqrestore(&sched_lock, flags);

    proc_remove(sched_proc_entry);
    pr_info("kelp: AI inference scheduler cleaned up\n");
}
