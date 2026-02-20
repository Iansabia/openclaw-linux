/*
 * clawd-linux :: libclawd-security
 * fs_perm.c - Filesystem permission checks
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/fs_perm.h>
#include <clawd/log.h>

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- helpers ------------------------------------------------------------ */

/**
 * Return true if the normalised path contains a ".." component that would
 * escape above the starting point.
 *
 * We work on the raw string *before* realpath so that we catch attempts
 * to use "../" even when the target directory does not yet exist.
 */
static bool has_traversal(const char *path)
{
    if (!path)
        return true;

    /*
     * Walk through path components.  We track a depth counter: every
     * non-".." component increments it, every ".." decrements it.
     * If depth goes negative the path escapes upward.
     */
    const char *p = path;

    /* Skip leading slash for absolute paths. */
    if (*p == '/')
        p++;

    int depth = 0;

    while (*p) {
        /* Find the end of this component. */
        const char *slash = strchr(p, '/');
        size_t comp_len = slash ? (size_t)(slash - p) : strlen(p);

        if (comp_len == 2 && p[0] == '.' && p[1] == '.') {
            depth--;
            if (depth < 0)
                return true;
        } else if (comp_len == 1 && p[0] == '.') {
            /* "." -- ignore, does not change depth */
        } else if (comp_len > 0) {
            depth++;
        }

        if (!slash)
            break;
        p = slash + 1;
    }

    return false;
}

/* ---- public API --------------------------------------------------------- */

int clawd_fs_check_perm(const char *path, clawd_perm_t perm)
{
    if (!path)
        return -1;

    int mode = 0;
    if (perm & CLAWD_PERM_READ)
        mode |= R_OK;
    if (perm & CLAWD_PERM_WRITE)
        mode |= W_OK;
    if (perm & CLAWD_PERM_EXEC)
        mode |= X_OK;

    if (mode == 0)
        mode = F_OK;

    if (access(path, mode) == 0)
        return 0;

    return -1;
}

bool clawd_fs_is_safe_path(const char *path)
{
    if (!path || path[0] == '\0')
        return false;

    /* Reject embedded NUL bytes (checked via strlen mismatch with pointer
     * arithmetic -- but since C strings are NUL-terminated this is inherently
     * handled; the real concern is at the calling boundary). */

    /* Reject raw traversal sequences. */
    if (has_traversal(path))
        return false;

    /* If the path exists, resolve it and ensure it does not differ
     * unexpectedly due to symlinks.  For a non-existent path we
     * accept it after the traversal check above. */
    struct stat st;
    if (lstat(path, &st) == 0) {
        if (S_ISLNK(st.st_mode)) {
            /* Follow the symlink and resolve canonically. */
            char resolved[PATH_MAX];
            if (!realpath(path, resolved))
                return false;

            /* If the original path was absolute, the resolved path should
             * share the same leading directory prefix.  We cannot easily
             * determine "escape" without a base, so we just ensure it
             * resolved successfully and is itself free of traversal. */
            if (has_traversal(resolved))
                return false;
        }
    }

    return true;
}

int clawd_fs_resolve_safe(const char *base, const char *relative,
                          char *out, size_t out_len)
{
    if (!base || !relative || !out || out_len == 0)
        return -1;

    /* base must be an absolute path. */
    if (base[0] != '/')
        return -1;

    /* Reject relative paths that start with '/' (absolute override). */
    if (relative[0] == '/')
        return -1;

    /* Build the combined path. */
    char combined[PATH_MAX];
    int n = snprintf(combined, sizeof(combined), "%s/%s", base, relative);
    if (n < 0 || (size_t)n >= sizeof(combined))
        return -1;

    /* Resolve to a canonical path. */
    char resolved[PATH_MAX];
    if (!realpath(combined, resolved)) {
        /* If the target does not exist, we fall back to manual traversal
         * checking on the combined string. */
        if (errno == ENOENT) {
            if (has_traversal(combined))
                return -1;
            /* Use the combined path as-is. */
            if (strlen(combined) >= out_len)
                return -1;
            strncpy(out, combined, out_len);
            out[out_len - 1] = '\0';
        } else {
            return -1;
        }
    } else {
        /* Verify that the resolved path starts with the base directory. */
        char resolved_base[PATH_MAX];
        if (!realpath(base, resolved_base))
            return -1;

        size_t base_len = strlen(resolved_base);

        /* The resolved path must start with the resolved base. */
        if (strncmp(resolved, resolved_base, base_len) != 0)
            return -1;

        /* After the base prefix there must be either a '/' or end-of-string
         * (the path IS the base directory itself). */
        if (resolved[base_len] != '\0' && resolved[base_len] != '/')
            return -1;

        if (strlen(resolved) >= out_len)
            return -1;

        strncpy(out, resolved, out_len);
        out[out_len - 1] = '\0';
    }

    return 0;
}

bool clawd_fs_check_ownership(const char *path, uid_t expected_uid)
{
    if (!path)
        return false;

    struct stat st;
    if (lstat(path, &st) != 0)
        return false;

    return st.st_uid == expected_uid;
}

int clawd_fs_scan_permissions(const char *dir, int max_depth)
{
    if (!dir)
        return -1;

    DIR *dp = opendir(dir);
    if (!dp) {
        CLAWD_WARN("fs_perm: cannot open directory: %s (%s)",
                   dir, strerror(errno));
        return -1;
    }

    int issues = 0;
    struct dirent *entry;

    while ((entry = readdir(dp)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char fullpath[PATH_MAX];
        int n = snprintf(fullpath, sizeof(fullpath), "%s/%s",
                         dir, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(fullpath))
            continue;

        struct stat st;
        if (lstat(fullpath, &st) != 0)
            continue;

        /* Check for world-writable files/directories. */
        if (st.st_mode & S_IWOTH) {
            CLAWD_WARN("fs_perm: world-writable: %s (mode %04o)",
                       fullpath, (unsigned)(st.st_mode & 07777));
            issues++;
        }

        /* Check for setuid/setgid binaries. */
        if (S_ISREG(st.st_mode)) {
            if (st.st_mode & S_ISUID) {
                CLAWD_WARN("fs_perm: setuid binary: %s (mode %04o)",
                           fullpath, (unsigned)(st.st_mode & 07777));
                issues++;
            }
            if (st.st_mode & S_ISGID) {
                CLAWD_WARN("fs_perm: setgid binary: %s (mode %04o)",
                           fullpath, (unsigned)(st.st_mode & 07777));
                issues++;
            }
        }

        /* Check for symlinks pointing outside the scanned tree. */
        if (S_ISLNK(st.st_mode)) {
            char target[PATH_MAX];
            ssize_t tlen = readlink(fullpath, target, sizeof(target) - 1);
            if (tlen > 0) {
                target[tlen] = '\0';
                /* Resolve and check if it escapes the base dir. */
                char resolved[PATH_MAX];
                if (realpath(fullpath, resolved)) {
                    if (strncmp(resolved, dir, strlen(dir)) != 0) {
                        CLAWD_WARN("fs_perm: symlink escapes base: %s -> %s",
                                   fullpath, target);
                        issues++;
                    }
                }
            }
        }

        /* Recurse into subdirectories. */
        if (S_ISDIR(st.st_mode) && max_depth > 0) {
            int sub = clawd_fs_scan_permissions(fullpath, max_depth - 1);
            if (sub > 0)
                issues += sub;
        }
    }

    closedir(dp);
    return issues;
}
