/*
 * kelp-linux :: libkelp-security
 * fs_perm.h - Filesystem permission checks
 *
 * Utilities for checking file permissions, detecting path traversal attacks,
 * safe path resolution, and scanning directory trees for permission issues.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_FS_PERM_H
#define KELP_FS_PERM_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Permission flags (bit-field, may be OR'd together). */
typedef enum {
    KELP_PERM_READ  = 1,
    KELP_PERM_WRITE = 2,
    KELP_PERM_EXEC  = 4
} kelp_perm_t;

/**
 * Check whether the current process has the requested permission(s) on @p path.
 *
 * Uses access(2) internally.
 *
 * @param path  Filesystem path to check.
 * @param perm  Bitmask of KELP_PERM_* flags.
 * @return 0 if the permission is granted, -1 if denied or on error.
 */
int kelp_fs_check_perm(const char *path, kelp_perm_t perm);

/**
 * Return true if @p path is safe:
 *
 *   - No ".." components after normalisation.
 *   - Does not follow symlinks that escape the expected directory tree.
 *   - Does not contain NUL bytes or other invalid sequences.
 *
 * @param path  The path to inspect.
 * @return true if safe, false otherwise.
 */
bool kelp_fs_is_safe_path(const char *path);

/**
 * Safely resolve @p relative within @p base.
 *
 * The resolved path is written to @p out (up to @p out_len bytes including
 * the NUL terminator).  The function guarantees that the result does not
 * escape @p base via traversal or symlinks.
 *
 * @param base      The allowed base directory (must be an absolute path).
 * @param relative  The relative path to resolve.
 * @param out       Output buffer for the resolved path.
 * @param out_len   Size of the output buffer.
 * @return 0 on success, -1 if the resolved path escapes @p base or on error.
 */
int kelp_fs_resolve_safe(const char *base, const char *relative,
                          char *out, size_t out_len);

/**
 * Check whether @p path is owned by @p expected_uid.
 *
 * @param path          Filesystem path to check (lstat, not stat).
 * @param expected_uid  Expected owner UID.
 * @return true if the file exists and is owned by @p expected_uid.
 */
bool kelp_fs_check_ownership(const char *path, uid_t expected_uid);

/**
 * Recursively scan @p dir for permission issues.
 *
 * Issues detected include world-writable files/directories, setuid/setgid
 * binaries, and files not owned by the current user.  Each issue is logged
 * via the kelp logging subsystem.
 *
 * @param dir        Directory to scan.
 * @param max_depth  Maximum recursion depth (0 = scan only @p dir itself).
 * @return Number of issues found, or -1 on error.
 */
int kelp_fs_scan_permissions(const char *dir, int max_depth);

#ifdef __cplusplus
}
#endif

#endif /* KELP_FS_PERM_H */
