/*
 * clawd-linux :: libclawd-agents
 * sandbox/sandbox_internal.h - Internal types shared across sandbox subsystem
 *
 * This header is NOT part of the public API. It is shared between
 * sandbox.c, cgroup.c, and other sandbox implementation files.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_SANDBOX_INTERNAL_H
#define CLAWD_SANDBOX_INTERNAL_H

#ifdef __linux__

typedef struct clawd_cgroup {
    char path[512];    /* /sys/fs/cgroup/clawd/sandbox-{id} */
} clawd_cgroup_t;

#else /* !__linux__ */

typedef struct clawd_cgroup {
    int dummy;
} clawd_cgroup_t;

#endif /* __linux__ */

#endif /* CLAWD_SANDBOX_INTERNAL_H */
