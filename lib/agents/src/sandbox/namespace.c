/*
 * clawd-linux :: libclawd-agents
 * sandbox/namespace.c - Linux namespace setup (user, PID, mount, network, UTS, IPC)
 *
 * Uses clone() with namespace flags to create isolated containers.
 * UID/GID mapping via /proc/pid/uid_map and /proc/pid/gid_map.
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/sandbox.h>
#include <clawd/log.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef __linux__

#include <sched.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>

#define CLONE_FLAGS (CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUSER | \
                     CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWIPC)
#define STACK_SIZE  (1024 * 1024)  /* 1 MB child stack */

/*
 * Write a UID or GID mapping into /proc/<pid>/uid_map or gid_map.
 *
 * Format: "<inside_id> <outside_id> <count>\n"
 * We map a single UID/GID: 0 inside -> host UID/GID outside.
 */
int clawd_ns_write_id_map(pid_t pid, const char *map_file,
                          unsigned int inside_id,
                          unsigned int outside_id)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/%s", (int)pid, map_file);

    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        CLAWD_ERROR("namespace: cannot open %s: %s", path, strerror(errno));
        return -1;
    }

    char mapping[64];
    int len = snprintf(mapping, sizeof(mapping), "%u %u 1\n", inside_id, outside_id);

    if (write(fd, mapping, (size_t)len) != len) {
        CLAWD_ERROR("namespace: failed to write %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

/*
 * Disable setgroups for the user namespace.
 * Required before writing gid_map on some kernels.
 */
int clawd_ns_deny_setgroups(pid_t pid)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/setgroups", (int)pid);

    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        /* setgroups file may not exist on older kernels -- not fatal */
        return 0;
    }

    const char *deny = "deny";
    if (write(fd, deny, strlen(deny)) < 0) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

/*
 * Set up UID and GID mappings for a child process in a new user namespace.
 *
 * Maps UID 0 (root inside namespace) to the specified host UID,
 * and GID 0 to the specified host GID.
 */
int clawd_ns_setup_user_mapping(pid_t child_pid, uid_t host_uid, gid_t host_gid)
{
    /* Must deny setgroups before writing gid_map */
    if (clawd_ns_deny_setgroups(child_pid) != 0) {
        CLAWD_WARN("namespace: failed to deny setgroups");
    }

    if (clawd_ns_write_id_map(child_pid, "uid_map", 0, (unsigned int)host_uid) != 0) {
        return -1;
    }

    if (clawd_ns_write_id_map(child_pid, "gid_map", 0, (unsigned int)host_gid) != 0) {
        return -1;
    }

    return 0;
}

/*
 * Check if user namespaces are usable.
 */
bool clawd_ns_user_ns_available(void)
{
    /* Check /proc/sys/kernel/unprivileged_userns_clone */
    FILE *fp = fopen("/proc/sys/kernel/unprivileged_userns_clone", "r");
    if (fp) {
        int val = 0;
        if (fscanf(fp, "%d", &val) == 1 && val == 0) {
            fclose(fp);
            return false;
        }
        fclose(fp);
    }

    /* Try to create a user namespace */
    pid_t pid = (pid_t)syscall(__NR_clone, CLONE_NEWUSER | SIGCHLD, NULL);
    if (pid < 0) {
        return false;
    } else if (pid == 0) {
        _exit(0);
    } else {
        int status;
        waitpid(pid, &status, 0);
        return true;
    }
}

#else /* !__linux__ */

bool clawd_ns_user_ns_available(void)
{
    return false;
}

int clawd_ns_setup_user_mapping(pid_t child_pid, uid_t host_uid, gid_t host_gid)
{
    (void)child_pid;
    (void)host_uid;
    (void)host_gid;
    CLAWD_WARN("namespace: user namespaces not available on this platform");
    return -1;
}

#endif /* __linux__ */
