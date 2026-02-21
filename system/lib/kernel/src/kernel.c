/*
 * kernel.c — Userspace library for /dev/kelp IPC
 *
 * Wraps open/read/write/ioctl for the kelp kernel module character device.
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/kernel.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define RECV_BUF_SIZE (64 * 1024)

int kelp_kernel_open(void)
{
    return open(KELP_DEVICE_PATH, O_RDWR);
}

int kelp_kernel_close(int fd)
{
    return close(fd);
}

int kelp_kernel_send(int fd, const char *msg, size_t len)
{
    if (!msg || len == 0)
        return -1;

    ssize_t written = write(fd, msg, len);
    if (written < 0)
        return -1;

    return 0;
}

char *kelp_kernel_recv(int fd, size_t *len)
{
    char *buf = malloc(RECV_BUF_SIZE);
    if (!buf)
        return NULL;

    ssize_t n = read(fd, buf, RECV_BUF_SIZE - 1);
    if (n < 0) {
        free(buf);
        return NULL;
    }

    buf[n] = '\0';

    if (len)
        *len = (size_t)n;

    return buf;
}

int kelp_kernel_get_stats(int fd, struct kelp_kstats *stats)
{
    if (!stats)
        return -1;
    return ioctl(fd, KELP_IOC_GET_STATS, stats);
}

int kelp_kernel_get_version(int fd, struct kelp_kversion *ver)
{
    if (!ver)
        return -1;
    return ioctl(fd, KELP_IOC_GET_VERSION, ver);
}

int kelp_kernel_get_status(int fd, struct kelp_kstatus *status)
{
    if (!status)
        return -1;
    return ioctl(fd, KELP_IOC_QUERY_STATUS, status);
}

bool kelp_kernel_available(void)
{
    struct stat st;
    if (stat(KELP_DEVICE_PATH, &st) != 0)
        return false;

    int fd = open(KELP_DEVICE_PATH, O_RDWR);
    if (fd < 0)
        return false;

    close(fd);
    return true;
}

/* ---- AI Primitive wrappers ---------------------------------------------- */

int kelp_kernel_submit_infer(int fd, struct kelp_infer_task *task)
{
    if (!task)
        return -1;
    return ioctl(fd, KELP_IOC_SUBMIT_INFER, task);
}

int kelp_kernel_poll_infer(int fd, struct kelp_infer_task *task)
{
    if (!task)
        return -1;
    return ioctl(fd, KELP_IOC_POLL_INFER, task);
}

int kelp_kernel_get_semfs_events(int fd, struct kelp_semfs_batch *batch)
{
    if (!batch)
        return -1;
    return ioctl(fd, KELP_IOC_SEMFS_EVENTS, batch);
}

int kelp_kernel_semfs_watch(int fd, struct kelp_semfs_watch *watch)
{
    if (!watch)
        return -1;
    return ioctl(fd, KELP_IOC_SEMFS_WATCH, watch);
}

int kelp_kernel_get_ai_status(int fd, struct kelp_ai_status *status)
{
    if (!status)
        return -1;
    return ioctl(fd, KELP_IOC_AI_STATUS, status);
}
