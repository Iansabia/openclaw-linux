/*
 * kelp-linux :: libkelp-security
 * path_scan.h - Path scanning / filtering
 *
 * A pattern-based path filter that determines whether a given filesystem
 * path should be allowed or denied.  Patterns use fnmatch(3) glob syntax.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_PATH_SCAN_H
#define KELP_PATH_SCAN_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque scanner handle. */
typedef struct kelp_path_scanner kelp_path_scanner_t;

/**
 * Create a new, empty path scanner.
 *
 * @return A scanner handle, or NULL on allocation failure.
 */
kelp_path_scanner_t *kelp_path_scanner_new(void);

/**
 * Free a scanner and all internally-owned memory.
 *
 * @param s  Scanner handle (may be NULL).
 */
void kelp_path_scanner_free(kelp_path_scanner_t *s);

/**
 * Add a glob pattern to the scanner.
 *
 * Patterns are evaluated in insertion order.  The first matching pattern
 * determines the result.
 *
 * @param s             Scanner handle.
 * @param glob_pattern  fnmatch-style pattern (e.g. "*.env", ".ssh/*").
 * @param deny          If true, matching paths are denied; otherwise allowed.
 */
void kelp_path_scanner_add_pattern(kelp_path_scanner_t *s,
                                    const char *glob_pattern,
                                    bool deny);

/**
 * Check whether @p path is allowed by the scanner.
 *
 * Iterates through all patterns in order.  The first match determines the
 * result.  If no pattern matches, the path is allowed by default.
 *
 * @param s     Scanner handle.
 * @param path  Filesystem path to check.
 * @return true if the path is allowed, false if denied.
 */
bool kelp_path_scanner_check(const kelp_path_scanner_t *s, const char *path);

/**
 * Add a set of sensible default deny patterns.
 *
 * Blocked by default:
 *   *.env, .env, .ssh/*, *.pem, *.key, credentials*,
 *   *secret*, /proc/*, /sys/*
 *
 * @param s  Scanner handle.
 */
void kelp_path_scanner_add_defaults(kelp_path_scanner_t *s);

#ifdef __cplusplus
}
#endif

#endif /* KELP_PATH_SCAN_H */
