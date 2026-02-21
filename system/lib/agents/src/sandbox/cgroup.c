/*
 * kelp-linux :: libkelp-agents
 * sandbox/cgroup.c - cgroup v2 resource limits
 *
 * Creates a cgroup under /sys/fs/cgroup/kelp/sandbox-{id}/
 * and configures memory.max, cpu.max, and pids.max.
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/sandbox.h>
#include <kelp/log.h>

#include "sandbox_internal.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef __linux__

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#define CGROUP_BASE "/sys/fs/cgroup/kelp"

static int write_file(const char *path, const char *content)
{
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) {
        KELP_WARN("cgroup: cannot write %s: %s", path, strerror(errno));
        return -1;
    }

    size_t len = strlen(content);
    ssize_t written = write(fd, content, len);
    close(fd);

    if ((size_t)written != len) {
        KELP_WARN("cgroup: incomplete write to %s", path);
        return -1;
    }

    return 0;
}

/*
 * Create a cgroup directory for the sandbox.
 * Returns a malloc'd cgroup handle, or NULL on failure.
 */
kelp_cgroup_t *kelp_cgroup_create(unsigned int sandbox_id)
{
    kelp_cgroup_t *cg = (kelp_cgroup_t *)calloc(1, sizeof(*cg));
    if (!cg) return NULL;

    /* Ensure base directory exists */
    if (mkdir(CGROUP_BASE, 0755) != 0 && errno != EEXIST) {
        KELP_WARN("cgroup: cannot create %s: %s", CGROUP_BASE, strerror(errno));
        /* Non-fatal: might not have permissions */
    }

    snprintf(cg->path, sizeof(cg->path), "%s/sandbox-%u", CGROUP_BASE, sandbox_id);

    if (mkdir(cg->path, 0755) != 0 && errno != EEXIST) {
        KELP_ERROR("cgroup: cannot create %s: %s", cg->path, strerror(errno));
        free(cg);
        return NULL;
    }

    KELP_DEBUG("cgroup: created %s", cg->path);
    return cg;
}

/*
 * Set memory limit in MB.
 */
int kelp_cgroup_set_memory(kelp_cgroup_t *cg, int limit_mb)
{
    if (!cg || limit_mb <= 0) return -1;

    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "%s/memory.max", cg->path);

    char value[64];
    snprintf(value, sizeof(value), "%lld", (long long)limit_mb * 1024 * 1024);

    return write_file(filepath, value);
}

/*
 * Set CPU limit as number of cores (via cpu.max).
 *
 * cpu.max format: "$MAX $PERIOD"
 * For N cores at 100000us period: "N*100000 100000"
 */
int kelp_cgroup_set_cpu(kelp_cgroup_t *cg, int cores)
{
    if (!cg || cores <= 0) return -1;

    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "%s/cpu.max", cg->path);

    char value[64];
    int period = 100000;
    int quota  = cores * period;
    snprintf(value, sizeof(value), "%d %d", quota, period);

    return write_file(filepath, value);
}

/*
 * Set PID limit.
 */
int kelp_cgroup_set_pids(kelp_cgroup_t *cg, int max_pids)
{
    if (!cg || max_pids <= 0) return -1;

    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "%s/pids.max", cg->path);

    char value[64];
    snprintf(value, sizeof(value), "%d", max_pids);

    return write_file(filepath, value);
}

/*
 * Add a process to this cgroup.
 */
int kelp_cgroup_add_pid(kelp_cgroup_t *cg, pid_t pid)
{
    if (!cg) return -1;

    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "%s/cgroup.procs", cg->path);

    char value[32];
    snprintf(value, sizeof(value), "%d", (int)pid);

    return write_file(filepath, value);
}

/*
 * Destroy the cgroup directory.
 * The cgroup must have no running processes.
 */
void kelp_cgroup_destroy(kelp_cgroup_t *cg)
{
    if (!cg) return;

    if (rmdir(cg->path) != 0 && errno != ENOENT) {
        KELP_WARN("cgroup: cannot remove %s: %s (may still have processes)",
                    cg->path, strerror(errno));
    } else {
        KELP_DEBUG("cgroup: destroyed %s", cg->path);
    }

    free(cg);
}

#else /* !__linux__ */

kelp_cgroup_t *kelp_cgroup_create(unsigned int sandbox_id)
{
    (void)sandbox_id;
    KELP_WARN("cgroup: not available on this platform");
    return NULL;
}

int kelp_cgroup_set_memory(kelp_cgroup_t *cg, int limit_mb)
{
    (void)cg; (void)limit_mb;
    return -1;
}

int kelp_cgroup_set_cpu(kelp_cgroup_t *cg, int cores)
{
    (void)cg; (void)cores;
    return -1;
}

int kelp_cgroup_set_pids(kelp_cgroup_t *cg, int max_pids)
{
    (void)cg; (void)max_pids;
    return -1;
}

int kelp_cgroup_add_pid(kelp_cgroup_t *cg, pid_t pid)
{
    (void)cg; (void)pid;
    return -1;
}

void kelp_cgroup_destroy(kelp_cgroup_t *cg)
{
    (void)cg;
}

#endif /* __linux__ */
