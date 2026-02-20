/*
 * clawd-linux :: libclawd-agents
 * sandbox/mount.c - Mount namespace setup
 *
 * Configures the filesystem view inside the sandbox:
 *   - Bind-mount workspace directory read-write
 *   - Mount everything else read-only
 *   - Fresh /tmp (tmpfs) and /proc
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/sandbox.h>
#include <clawd/log.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef __linux__

#include <errno.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Make the root filesystem private so mount changes don't propagate
 * to the host.
 */
static int make_root_private(void)
{
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        CLAWD_ERROR("mount: failed to make root private: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * Remount the root filesystem as read-only.
 */
static int make_root_readonly(void)
{
    if (mount("none", "/", NULL, MS_REMOUNT | MS_RDONLY | MS_BIND, NULL) != 0) {
        CLAWD_WARN("mount: failed to remount root read-only: %s", strerror(errno));
        /* Non-fatal: some systems don't support this combination */
    }
    return 0;
}

/*
 * Bind-mount a directory.
 *
 * @param src       Source path.
 * @param dst       Destination path.
 * @param readonly  If true, remount read-only after binding.
 */
static int bind_mount(const char *src, const char *dst, bool readonly)
{
    /* Ensure destination directory exists */
    mkdir(dst, 0755);

    if (mount(src, dst, NULL, MS_BIND | MS_REC, NULL) != 0) {
        CLAWD_ERROR("mount: bind mount %s -> %s failed: %s",
                    src, dst, strerror(errno));
        return -1;
    }

    if (readonly) {
        if (mount(NULL, dst, NULL, MS_REMOUNT | MS_BIND | MS_RDONLY | MS_REC, NULL) != 0) {
            CLAWD_WARN("mount: failed to make %s read-only: %s", dst, strerror(errno));
        }
    }

    CLAWD_DEBUG("mount: bind %s -> %s %s", src, dst, readonly ? "(ro)" : "(rw)");
    return 0;
}

/*
 * Mount a fresh tmpfs at the given path.
 */
static int mount_tmpfs(const char *path, size_t size_mb)
{
    mkdir(path, 01777);

    char opts[64];
    snprintf(opts, sizeof(opts), "size=%zuM,mode=1777", size_mb);

    if (mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NODEV, opts) != 0) {
        CLAWD_ERROR("mount: tmpfs at %s failed: %s", path, strerror(errno));
        return -1;
    }

    CLAWD_DEBUG("mount: tmpfs at %s (%zuMB)", path, size_mb);
    return 0;
}

/*
 * Mount /proc inside the sandbox.
 */
static int mount_proc(void)
{
    mkdir("/proc", 0555);

    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0) {
        CLAWD_ERROR("mount: /proc failed: %s", strerror(errno));
        return -1;
    }

    CLAWD_DEBUG("mount: /proc mounted");
    return 0;
}

/*
 * Set up the full mount namespace for a sandbox.
 *
 * This function should be called inside the cloned child process,
 * after the user namespace mapping has been applied.
 *
 * @param workspace       Path to bind-mount read-write.
 * @param readonly_paths  Additional paths to bind-mount read-only.
 * @param readonly_count  Number of read-only paths.
 * @return 0 on success, -1 on error.
 */
int clawd_mount_setup(const char *workspace,
                      const char **readonly_paths,
                      int readonly_count)
{
    /* Step 1: Make root mount private */
    if (make_root_private() != 0) return -1;

    /* Step 2: Remount root read-only */
    make_root_readonly();

    /* Step 3: Mount workspace read-write */
    if (workspace) {
        if (bind_mount(workspace, workspace, false) != 0) {
            return -1;
        }
    }

    /* Step 4: Mount additional read-only paths */
    for (int i = 0; i < readonly_count; i++) {
        if (readonly_paths[i]) {
            bind_mount(readonly_paths[i], readonly_paths[i], true);
        }
    }

    /* Step 5: Fresh /tmp */
    mount_tmpfs("/tmp", 64);  /* 64 MB tmpfs */

    /* Step 6: Fresh /proc */
    mount_proc();

    return 0;
}

#else /* !__linux__ */

int clawd_mount_setup(const char *workspace,
                      const char **readonly_paths,
                      int readonly_count)
{
    (void)workspace;
    (void)readonly_paths;
    (void)readonly_count;
    CLAWD_WARN("mount: mount namespace setup not available on this platform");
    return -1;
}

#endif /* __linux__ */
