/*
 * kelp_accel.c — Accelerator management stubs
 *
 * Phase 1 stub implementation. Returns empty accelerator list
 * and validates reserve requests without actual GPU/NPU interaction.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>

#include "kelp_internal.h"
#include "../include/kelp/kelp_ai.h"

/*
 * List accelerators (ioctl handler).
 * Phase 1: returns count=0 (no accelerators detected).
 */
int kelp_accel_list(unsigned long arg)
{
    struct kelp_accel_list list;

    memset(&list, 0, sizeof(list));
    list.count = 0;

    if (copy_to_user((void __user *)arg, &list, sizeof(list)))
        return -EFAULT;

    return 0;
}

/*
 * Reserve accelerator memory (ioctl handler).
 * Phase 1: validates input but always returns success (no-op).
 */
int kelp_accel_reserve(unsigned long arg)
{
    struct kelp_accel_reserve req;

    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;

    /* Validate: no accelerators exist in phase 1 */
    if (req.accel_id >= KELP_ACCEL_MAX)
        return -EINVAL;

    if (req.bytes == 0)
        return -EINVAL;

    /* Stub: return success without actually reserving anything */
    if (kelp_get_log_level() >= 2)
        pr_info("kelp: accel reserve stub: id=%u bytes=%llu\n",
                req.accel_id, req.bytes);

    return 0;
}

/* Stats accessor */
uint32_t kelp_accel_get_count(void)
{
    return 0;  /* Phase 1: no accelerators */
}

/* /proc/kelp/accelerators */
static int accel_proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "Kelp Accelerator Management\n");
    seq_printf(m, "===========================\n");
    seq_printf(m, "Detected accelerators: 0\n");
    seq_printf(m, "\n");
    seq_printf(m, "  (no accelerators detected — phase 1 stub)\n");
    seq_printf(m, "\n");
    seq_printf(m, "Supported types:\n");
    seq_printf(m, "  CUDA  (type=%d)\n", KELP_ACCEL_CUDA);
    seq_printf(m, "  ROCm  (type=%d)\n", KELP_ACCEL_ROCM);
    seq_printf(m, "  NPU   (type=%d)\n", KELP_ACCEL_NPU);
    return 0;
}

static int accel_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, accel_proc_show, NULL);
}

static const struct proc_ops accel_proc_ops = {
    .proc_open    = accel_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static struct proc_dir_entry *accel_proc_entry;

int kelp_accel_init(struct proc_dir_entry *proc_dir)
{
    accel_proc_entry = proc_create("accelerators", 0444, proc_dir,
                                   &accel_proc_ops);
    if (!accel_proc_entry) {
        pr_err("kelp: failed to create /proc/kelp/accelerators\n");
        return -ENOMEM;
    }

    pr_info("kelp: accelerator management initialized (phase 1 stub)\n");
    return 0;
}

void kelp_accel_exit(void)
{
    proc_remove(accel_proc_entry);
    pr_info("kelp: accelerator management cleaned up\n");
}
