/*
 * kelp-linux :: libkelp-agents
 * sandbox/sandbox_internal.h - Internal types shared across sandbox subsystem
 *
 * This header is NOT part of the public API. It is shared between
 * sandbox.c, cgroup.c, and other sandbox implementation files.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_SANDBOX_INTERNAL_H
#define KELP_SANDBOX_INTERNAL_H

#ifdef __linux__

typedef struct kelp_cgroup {
    char path[512];    /* /sys/fs/cgroup/kelp/sandbox-{id} */
} kelp_cgroup_t;

#else /* !__linux__ */

typedef struct kelp_cgroup {
    int dummy;
} kelp_cgroup_t;

#endif /* __linux__ */

#endif /* KELP_SANDBOX_INTERNAL_H */
