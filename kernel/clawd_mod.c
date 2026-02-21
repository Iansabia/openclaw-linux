/*
 * clawd_mod.c — Clawd Kernel module
 *
 * Provides /dev/clawd chardev for userspace IPC, /proc/clawd for stats,
 * and netfilter hooks for network-aware AI.
 *
 * Build: make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 * Load:  sudo insmod clawd.ko
 * Unload: sudo rmmod clawd
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

#include "clawd_kernel.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Clawd Project");
MODULE_DESCRIPTION("Clawd Kernel — AI Assistant Kernel Module");
MODULE_VERSION("0.1.0");

/* Module parameters */
static int log_level = 1;  /* 0=quiet, 1=info, 2=debug */
module_param(log_level, int, 0644);
MODULE_PARM_DESC(log_level, "Log verbosity (0=quiet, 1=info, 2=debug)");

static int enable_netfilter = 1;
module_param(enable_netfilter, int, 0644);
MODULE_PARM_DESC(enable_netfilter, "Enable netfilter hooks (0=off, 1=on)");

/* Global state */
static dev_t            clawd_dev;
static struct cdev      clawd_cdev;
static struct class    *clawd_class;
static struct device   *clawd_device;
static DEFINE_MUTEX(clawd_mutex);

/* Statistics */
static struct clawd_kstats stats;
static ktime_t module_start_time;
static atomic_t open_count = ATOMIC_INIT(0);

/* Message ring buffer for chardev IPC */
#define RING_SIZE 64
#define MSG_MAX_LEN CLAWD_MAX_MSG_SIZE

struct ring_msg {
    char   *data;
    size_t  len;
};

static struct ring_msg ring_buf[RING_SIZE];
static int ring_head;  /* Write position */
static int ring_tail;  /* Read position */
static DEFINE_SPINLOCK(ring_lock);
static DECLARE_WAIT_QUEUE_HEAD(read_queue);
static DECLARE_WAIT_QUEUE_HEAD(write_queue);

/* Forward declarations */
extern int  clawd_chardev_open(struct inode *inode, struct file *file);
extern int  clawd_chardev_release(struct inode *inode, struct file *file);
extern ssize_t clawd_chardev_read(struct file *file, char __user *buf,
                                   size_t count, loff_t *ppos);
extern ssize_t clawd_chardev_write(struct file *file, const char __user *buf,
                                    size_t count, loff_t *ppos);
extern long clawd_chardev_ioctl(struct file *file, unsigned int cmd,
                                 unsigned long arg);

extern int  clawd_procfs_init(void);
extern void clawd_procfs_exit(void);

extern int  clawd_netfilter_init(void);
extern void clawd_netfilter_exit(void);

/* File operations */
static const struct file_operations clawd_fops = {
    .owner          = THIS_MODULE,
    .open           = clawd_chardev_open,
    .release        = clawd_chardev_release,
    .read           = clawd_chardev_read,
    .write          = clawd_chardev_write,
    .unlocked_ioctl = clawd_chardev_ioctl,
};

/* Exported symbols for sub-modules */
struct clawd_kstats *clawd_get_stats(void) { return &stats; }
int clawd_get_log_level(void) { return log_level; }
int clawd_get_netfilter_enabled(void) { return enable_netfilter; }
ktime_t clawd_get_start_time(void) { return module_start_time; }
atomic_t *clawd_get_open_count(void) { return &open_count; }
struct mutex *clawd_get_mutex(void) { return &clawd_mutex; }

/* Ring buffer access */
struct ring_msg *clawd_get_ring(void) { return ring_buf; }
int *clawd_get_ring_head(void) { return &ring_head; }
int *clawd_get_ring_tail(void) { return &ring_tail; }
spinlock_t *clawd_get_ring_lock(void) { return &ring_lock; }
wait_queue_head_t *clawd_get_read_queue(void) { return &read_queue; }
wait_queue_head_t *clawd_get_write_queue(void) { return &write_queue; }

static int __init clawd_init(void)
{
    int ret;

    pr_info("clawd: initializing v%d.%d.%d\n",
            0, 1, 0);

    module_start_time = ktime_get_boottime();
    memset(&stats, 0, sizeof(stats));

    /* Allocate chardev region */
    ret = alloc_chrdev_region(&clawd_dev, 0, 1, CLAWD_DEVICE_NAME);
    if (ret < 0) {
        pr_err("clawd: failed to allocate chardev region: %d\n", ret);
        return ret;
    }

    /* Init and add cdev */
    cdev_init(&clawd_cdev, &clawd_fops);
    clawd_cdev.owner = THIS_MODULE;
    ret = cdev_add(&clawd_cdev, clawd_dev, 1);
    if (ret < 0) {
        pr_err("clawd: failed to add cdev: %d\n", ret);
        goto err_cdev;
    }

    /* Create device class */
    clawd_class = class_create(CLAWD_CLASS_NAME);
    if (IS_ERR(clawd_class)) {
        ret = PTR_ERR(clawd_class);
        pr_err("clawd: failed to create class: %d\n", ret);
        goto err_class;
    }

    /* Create device */
    clawd_device = device_create(clawd_class, NULL, clawd_dev, NULL,
                                  CLAWD_DEVICE_NAME);
    if (IS_ERR(clawd_device)) {
        ret = PTR_ERR(clawd_device);
        pr_err("clawd: failed to create device: %d\n", ret);
        goto err_device;
    }

    /* Initialize ring buffer */
    memset(ring_buf, 0, sizeof(ring_buf));
    ring_head = 0;
    ring_tail = 0;

    /* Initialize procfs */
    ret = clawd_procfs_init();
    if (ret < 0) {
        pr_warn("clawd: procfs init failed (non-fatal): %d\n", ret);
    }

    /* Initialize netfilter */
    if (enable_netfilter) {
        ret = clawd_netfilter_init();
        if (ret < 0) {
            pr_warn("clawd: netfilter init failed (non-fatal): %d\n", ret);
            enable_netfilter = 0;
        }
    }

    pr_info("clawd: module loaded (major=%d, minor=%d)\n",
            MAJOR(clawd_dev), MINOR(clawd_dev));
    pr_info("clawd: /dev/%s created\n", CLAWD_DEVICE_NAME);

    return 0;

err_device:
    class_destroy(clawd_class);
err_class:
    cdev_del(&clawd_cdev);
err_cdev:
    unregister_chrdev_region(clawd_dev, 1);
    return ret;
}

static void __exit clawd_exit(void)
{
    int i;

    pr_info("clawd: unloading module\n");

    /* Cleanup netfilter */
    if (enable_netfilter) {
        clawd_netfilter_exit();
    }

    /* Cleanup procfs */
    clawd_procfs_exit();

    /* Free ring buffer messages */
    for (i = 0; i < RING_SIZE; i++) {
        kfree(ring_buf[i].data);
        ring_buf[i].data = NULL;
    }

    /* Destroy device */
    device_destroy(clawd_class, clawd_dev);
    class_destroy(clawd_class);
    cdev_del(&clawd_cdev);
    unregister_chrdev_region(clawd_dev, 1);

    pr_info("clawd: module unloaded\n");
}

module_init(clawd_init);
module_exit(clawd_exit);
