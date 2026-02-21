/*
 * kelp-init.c — Kelp OS boot service
 *
 * Minimal init helper that ensures the kelp kernel module is loaded
 * and the gateway daemon is started. Designed to be called from
 * the BusyBox init system or systemd.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>

#define KELP_DEVICE     "/dev/kelp"
#define KELP_MODULE     "kelp"
#define KELP_GATEWAY    "/usr/bin/kelp-gateway"
#define KELP_CONFIG     "/etc/kelp/kelp.yaml"
#define KELP_LOGDIR     "/var/log/kelp"
#define WAIT_TIMEOUT_MS 3000
#define WAIT_INTERVAL_MS 100

static int run_command(const char *cmd)
{
    int status = system(cmd);
    if (status == -1)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int device_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0 && S_ISCHR(st.st_mode));
}

static int load_module(void)
{
    if (device_exists(KELP_DEVICE)) {
        printf("kelp-init: module already loaded\n");
        return 0;
    }

    printf("kelp-init: loading %s module...\n", KELP_MODULE);

    if (run_command("modprobe " KELP_MODULE) == 0)
        return 0;

    /* Fallback: try insmod directly */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "insmod /lib/modules/$(uname -r)/extra/%s.ko", KELP_MODULE);
    return run_command(cmd);
}

static int wait_for_device(void)
{
    int elapsed = 0;

    while (elapsed < WAIT_TIMEOUT_MS) {
        if (device_exists(KELP_DEVICE))
            return 0;
        usleep(WAIT_INTERVAL_MS * 1000);
        elapsed += WAIT_INTERVAL_MS;
    }

    fprintf(stderr, "kelp-init: timeout waiting for %s\n", KELP_DEVICE);
    return -1;
}

static int start_gateway(void)
{
    struct stat st;

    if (stat(KELP_GATEWAY, &st) != 0) {
        fprintf(stderr, "kelp-init: %s not found\n", KELP_GATEWAY);
        return -1;
    }

    printf("kelp-init: starting kelp-gateway daemon...\n");

    pid_t pid = fork();
    if (pid < 0) {
        perror("kelp-init: fork");
        return -1;
    }

    if (pid == 0) {
        /* Child: daemonize */
        setsid();

        int fd = open("/dev/null", O_RDWR);
        if (fd >= 0) {
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > 2)
                close(fd);
        }

        execl(KELP_GATEWAY, "kelp-gateway", "-d", NULL);
        _exit(127);
    }

    printf("kelp-init: gateway started (pid=%d)\n", pid);
    return 0;
}

int main(int argc, char *argv[])
{
    printf("kelp-init: Kelp OS boot service starting...\n");

    /* Ensure log directory */
    (void)mkdir(KELP_LOGDIR, 0755);

    /* Step 1: Load kernel module */
    if (load_module() != 0) {
        fprintf(stderr, "kelp-init: WARNING: failed to load kernel module\n");
    }

    /* Step 2: Wait for /dev/kelp */
    if (wait_for_device() != 0) {
        fprintf(stderr, "kelp-init: WARNING: device not available\n");
    }

    /* Step 3: Start gateway */
    if (start_gateway() != 0) {
        fprintf(stderr, "kelp-init: WARNING: failed to start gateway\n");
    }

    printf("kelp-init: boot sequence complete\n");
    return 0;
}
