/*
 * kernel.c — Userspace library for /dev/clawd IPC
 *
 * Wraps open/read/write/ioctl for the clawd kernel module character device.
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/kernel.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define RECV_BUF_SIZE (64 * 1024)

int clawd_kernel_open(void)
{
    return open(CLAWD_DEVICE_PATH, O_RDWR);
}

int clawd_kernel_close(int fd)
{
    return close(fd);
}

int clawd_kernel_send(int fd, const char *msg, size_t len)
{
    if (!msg || len == 0)
        return -1;

    ssize_t written = write(fd, msg, len);
    if (written < 0)
        return -1;

    return 0;
}

char *clawd_kernel_recv(int fd, size_t *len)
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

int clawd_kernel_get_stats(int fd, struct clawd_kstats *stats)
{
    if (!stats)
        return -1;
    return ioctl(fd, CLAWD_IOC_GET_STATS, stats);
}

int clawd_kernel_get_version(int fd, struct clawd_kversion *ver)
{
    if (!ver)
        return -1;
    return ioctl(fd, CLAWD_IOC_GET_VERSION, ver);
}

int clawd_kernel_get_status(int fd, struct clawd_kstatus *status)
{
    if (!status)
        return -1;
    return ioctl(fd, CLAWD_IOC_QUERY_STATUS, status);
}

bool clawd_kernel_available(void)
{
    struct stat st;
    if (stat(CLAWD_DEVICE_PATH, &st) != 0)
        return false;

    int fd = open(CLAWD_DEVICE_PATH, O_RDWR);
    if (fd < 0)
        return false;

    close(fd);
    return true;
}
