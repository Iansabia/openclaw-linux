/*
 * kelp-linux :: libkelp-security
 * timing.h - Timing-safe comparison utilities
 *
 * Provides constant-time memory comparison to prevent timing side-channel
 * attacks when comparing secrets (tokens, hashes, MACs, etc.).
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_TIMING_H
#define KELP_TIMING_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Constant-time comparison of two memory regions.
 *
 * Compares @p len bytes of @p a and @p b without short-circuiting on the
 * first mismatch.  The execution time depends only on @p len, never on the
 * content of the buffers, making it safe for comparing cryptographic secrets.
 *
 * @param a    First buffer (may be NULL only if @p len is 0).
 * @param b    Second buffer (may be NULL only if @p len is 0).
 * @param len  Number of bytes to compare.
 * @return true if the buffers are identical, false otherwise.
 *         Returns false if either pointer is NULL and @p len > 0.
 *         Returns true if @p len is 0 and both pointers are non-NULL.
 */
bool kelp_timing_safe_cmp(const void *a, const void *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* KELP_TIMING_H */
