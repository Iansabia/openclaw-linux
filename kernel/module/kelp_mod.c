/*
 * kelp_mod.c — Kelp Kernel module
 *
 * Provides /dev/kelp chardev for userspace IPC, /proc/kelp for stats,
 * and netfilter hooks for network-aware AI.
 *
 * Build: make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 * Load:  sudo insmod kelp.ko
 * Unload: sudo rmmod kelp
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/time64.h>
#include <linux/ktime.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "kelp_internal.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kelp Project");
MODULE_DESCRIPTION("Kelp OS — AI-First Operating System Kernel Module");
MODULE_VERSION("0.1.0");

/* Module parameters */
static int log_level = 1;  /* 0=quiet, 1=info, 2=debug */
module_param(log_level, int, 0644);
MODULE_PARM_DESC(log_level, "Log verbosity (0=quiet, 1=info, 2=debug)");

static int enable_netfilter = 1;
module_param(enable_netfilter, int, 0644);
MODULE_PARM_DESC(enable_netfilter, "Enable netfilter hooks (0=off, 1=on)");

/* Global state */
static dev_t            kelp_dev;
static struct cdev      kelp_cdev;
static struct class    *kelp_class;
static struct device   *kelp_device;
static DEFINE_MUTEX(kelp_mutex);

/* Statistics */
static struct kelp_kstats stats;
static ktime_t module_start_time;
static atomic_t open_count = ATOMIC_INIT(0);

/* Message ring buffer for chardev IPC */
#define RING_SIZE 64
#define MSG_MAX_LEN KELP_MAX_MSG_SIZE

static struct ring_msg ring_buf[RING_SIZE];
static int ring_head;  /* Write position */
static int ring_tail;  /* Read position */
static DEFINE_SPINLOCK(ring_lock);
static DECLARE_WAIT_QUEUE_HEAD(read_queue);
static DECLARE_WAIT_QUEUE_HEAD(write_queue);

/* File operations */
static const struct file_operations kelp_fops = {
    .owner          = THIS_MODULE,
    .open           = kelp_chardev_open,
    .release        = kelp_chardev_release,
    .read           = kelp_chardev_read,
    .write          = kelp_chardev_write,
    .unlocked_ioctl = kelp_chardev_ioctl,
};

/* Exported symbols for sub-modules */
struct kelp_kstats *kelp_get_stats(void) { return &stats; }
int kelp_get_log_level(void) { return log_level; }
int kelp_get_netfilter_enabled(void) { return enable_netfilter; }
ktime_t kelp_get_start_time(void) { return module_start_time; }
atomic_t *kelp_get_open_count(void) { return &open_count; }
struct mutex *kelp_get_mutex(void) { return &kelp_mutex; }

/* Ring buffer access */
struct ring_msg *kelp_get_ring(void) { return ring_buf; }
int *kelp_get_ring_head(void) { return &ring_head; }
int *kelp_get_ring_tail(void) { return &ring_tail; }
spinlock_t *kelp_get_ring_lock(void) { return &ring_lock; }
wait_queue_head_t *kelp_get_read_queue(void) { return &read_queue; }
wait_queue_head_t *kelp_get_write_queue(void) { return &write_queue; }

static int __init kelp_init(void)
{
    int ret;

    pr_info("kelp: initializing v%d.%d.%d\n",
            0, 1, 0);

    module_start_time = ktime_get_boottime();
    memset(&stats, 0, sizeof(stats));

    /* Allocate chardev region */
    ret = alloc_chrdev_region(&kelp_dev, 0, 1, KELP_DEVICE_NAME);
    if (ret < 0) {
        pr_err("kelp: failed to allocate chardev region: %d\n", ret);
        return ret;
    }

    /* Init and add cdev */
    cdev_init(&kelp_cdev, &kelp_fops);
    kelp_cdev.owner = THIS_MODULE;
    ret = cdev_add(&kelp_cdev, kelp_dev, 1);
    if (ret < 0) {
        pr_err("kelp: failed to add cdev: %d\n", ret);
        goto err_cdev;
    }

    /* Create device class */
    kelp_class = class_create(KELP_CLASS_NAME);
    if (IS_ERR(kelp_class)) {
        ret = PTR_ERR(kelp_class);
        pr_err("kelp: failed to create class: %d\n", ret);
        goto err_class;
    }

    /* Create device */
    kelp_device = device_create(kelp_class, NULL, kelp_dev, NULL,
                                  KELP_DEVICE_NAME);
    if (IS_ERR(kelp_device)) {
        ret = PTR_ERR(kelp_device);
        pr_err("kelp: failed to create device: %d\n", ret);
        goto err_device;
    }

    /* Initialize ring buffer */
    memset(ring_buf, 0, sizeof(ring_buf));
    ring_head = 0;
    ring_tail = 0;

    /* Initialize procfs */
    ret = kelp_procfs_init();
    if (ret < 0) {
        pr_warn("kelp: procfs init failed (non-fatal): %d\n", ret);
    }

    /* Initialize netfilter */
    if (enable_netfilter) {
        ret = kelp_netfilter_init();
        if (ret < 0) {
            pr_warn("kelp: netfilter init failed (non-fatal): %d\n", ret);
            enable_netfilter = 0;
        }
    }

    /* Initialize AI subsystems */
    {
        struct proc_dir_entry *pdir = kelp_procfs_get_dir();

        ret = kelp_ai_sched_init(pdir);
        if (ret < 0)
            pr_warn("kelp: AI scheduler init failed (non-fatal): %d\n", ret);

        ret = kelp_semfs_init(pdir);
        if (ret < 0)
            pr_warn("kelp: semantic FS init failed (non-fatal): %d\n", ret);

        ret = kelp_accel_init(pdir);
        if (ret < 0)
            pr_warn("kelp: accelerator init failed (non-fatal): %d\n", ret);
    }

    pr_info("kelp: module loaded (major=%d, minor=%d)\n",
            MAJOR(kelp_dev), MINOR(kelp_dev));
    pr_info("kelp: /dev/%s created\n", KELP_DEVICE_NAME);

    return 0;

err_device:
    class_destroy(kelp_class);
err_class:
    cdev_del(&kelp_cdev);
err_cdev:
    unregister_chrdev_region(kelp_dev, 1);
    return ret;
}

static void __exit kelp_exit(void)
{
    int i;

    pr_info("kelp: unloading module\n");

    /* Cleanup AI subsystems (reverse order) */
    kelp_accel_exit();
    kelp_semfs_exit();
    kelp_ai_sched_exit();

    /* Cleanup netfilter */
    if (enable_netfilter) {
        kelp_netfilter_exit();
    }

    /* Cleanup procfs */
    kelp_procfs_exit();

    /* Free ring buffer messages */
    for (i = 0; i < RING_SIZE; i++) {
        kfree(ring_buf[i].data);
        ring_buf[i].data = NULL;
    }

    /* Destroy device */
    device_destroy(kelp_class, kelp_dev);
    class_destroy(kelp_class);
    cdev_del(&kelp_cdev);
    unregister_chrdev_region(kelp_dev, 1);

    pr_info("kelp: module unloaded\n");
}

module_init(kelp_init);
module_exit(kelp_exit);
