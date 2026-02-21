/*
 * clawd_procfs.c — /proc/clawd runtime stats
 *
 * Provides human-readable and machine-parseable statistics
 * about the Clawd kernel module.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/ktime.h>
#include <linux/time64.h>

#include "clawd_kernel.h"

/* External accessors */
extern struct clawd_kstats *clawd_get_stats(void);
extern int clawd_get_log_level(void);
extern int clawd_get_netfilter_enabled(void);
extern ktime_t clawd_get_start_time(void);
extern atomic_t *clawd_get_open_count(void);

/* External netfilter log */
extern int clawd_nf_get_recent(char *buf, size_t buf_size);

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_stats;
static struct proc_dir_entry *proc_netfilter;

/*
 * /proc/clawd/stats — show module statistics
 */
static int stats_show(struct seq_file *m, void *v)
{
    struct clawd_kstats *st = clawd_get_stats();
    ktime_t now = ktime_get_boottime();
    s64 uptime_ns = ktime_to_ns(ktime_sub(now, clawd_get_start_time()));
    uint64_t uptime_sec = (uint64_t)(uptime_ns / NSEC_PER_SEC);
    uint64_t hours = uptime_sec / 3600;
    uint64_t minutes = (uptime_sec % 3600) / 60;
    uint64_t seconds = uptime_sec % 60;

    seq_printf(m, "clawd v0.1.0\n");
    seq_printf(m, "================\n");
    seq_printf(m, "Uptime:              %lluh%llum%llus\n", hours, minutes, seconds);
    seq_printf(m, "Messages processed:  %llu\n", st->messages_processed);
    seq_printf(m, "Bytes read:          %llu\n", st->bytes_read);
    seq_printf(m, "Bytes written:       %llu\n", st->bytes_written);
    seq_printf(m, "Active handles:      %d\n", atomic_read(clawd_get_open_count()));
    seq_printf(m, "Netfilter enabled:   %s\n",
               clawd_get_netfilter_enabled() ? "yes" : "no");
    seq_printf(m, "Netfilter packets:   %llu\n", st->netfilter_packets);
    seq_printf(m, "Netfilter blocked:   %llu\n", st->netfilter_blocked);
    seq_printf(m, "Log level:           %d\n", clawd_get_log_level());

    return 0;
}

static int stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, stats_show, NULL);
}

static const struct proc_ops stats_proc_ops = {
    .proc_open    = stats_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/*
 * /proc/clawd/netfilter — show recent network events
 */
static int netfilter_show(struct seq_file *m, void *v)
{
    char buf[4096];
    int len;

    seq_printf(m, "Recent Network Events\n");
    seq_printf(m, "=====================\n");

    if (!clawd_get_netfilter_enabled()) {
        seq_printf(m, "  (netfilter hooks disabled)\n");
        return 0;
    }

    len = clawd_nf_get_recent(buf, sizeof(buf));
    if (len > 0) {
        seq_printf(m, "%s", buf);
    } else {
        seq_printf(m, "  (no recent events)\n");
    }

    return 0;
}

static int netfilter_open(struct inode *inode, struct file *file)
{
    return single_open(file, netfilter_show, NULL);
}

static const struct proc_ops netfilter_proc_ops = {
    .proc_open    = netfilter_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

int clawd_procfs_init(void)
{
    /* Create /proc/clawd directory */
    proc_dir = proc_mkdir(CLAWD_PROC_NAME, NULL);
    if (!proc_dir) {
        pr_err("clawd: failed to create /proc/%s\n", CLAWD_PROC_NAME);
        return -ENOMEM;
    }

    /* Create /proc/clawd/stats */
    proc_stats = proc_create("stats", 0444, proc_dir, &stats_proc_ops);
    if (!proc_stats) {
        pr_err("clawd: failed to create /proc/%s/stats\n", CLAWD_PROC_NAME);
        proc_remove(proc_dir);
        return -ENOMEM;
    }

    /* Create /proc/clawd/netfilter */
    proc_netfilter = proc_create("netfilter", 0444, proc_dir, &netfilter_proc_ops);
    if (!proc_netfilter) {
        pr_err("clawd: failed to create /proc/%s/netfilter\n", CLAWD_PROC_NAME);
        proc_remove(proc_stats);
        proc_remove(proc_dir);
        return -ENOMEM;
    }

    pr_info("clawd: procfs entries created under /proc/%s\n", CLAWD_PROC_NAME);
    return 0;
}

void clawd_procfs_exit(void)
{
    proc_remove(proc_netfilter);
    proc_remove(proc_stats);
    proc_remove(proc_dir);
    pr_info("clawd: procfs entries removed\n");
}
