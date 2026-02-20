/*
 * clawd-linux :: libclawd-core
 * crypto.h - Cryptographic utilities (OpenSSL backend)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_CRYPTO_H
#define CLAWD_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Compute SHA-256 of `data` (len bytes) into `out` (32 bytes). */
void clawd_sha256(const void *data, size_t len, uint8_t out[32]);

/** Compute SHA-256 and write the hex digest into `out` (65 bytes incl. NUL). */
void clawd_sha256_hex(const void *data, size_t len, char out[65]);

/**
 * Compute HMAC-SHA256.
 * @param key   Key material.
 * @param klen  Key length in bytes.
 * @param data  Message data.
 * @param dlen  Message length in bytes.
 * @param out   Output buffer (32 bytes).
 */
void clawd_hmac_sha256(const void *key, size_t klen,
                       const void *data, size_t dlen,
                       uint8_t out[32]);

/**
 * Fill `buf` with `len` cryptographically-secure random bytes.
 * Returns 0 on success, -1 on failure.
 */
int clawd_random_bytes(void *buf, size_t len);

/**
 * Base64-encode `data`.  Returns a malloc'd NUL-terminated string.
 * The caller must free the result.  Returns NULL on failure.
 */
char *clawd_base64_encode(const void *data, size_t len);

/**
 * Base64-decode `b64`.
 * Returns a malloc'd buffer and sets `*out_len` to its size.
 * The caller must free the result.  Returns NULL on failure.
 */
uint8_t *clawd_base64_decode(const char *b64, size_t *out_len);

/**
 * Constant-time comparison of two buffers.
 * Returns 0 if equal, non-zero otherwise.
 */
int clawd_timing_safe_cmp(const void *a, const void *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_CRYPTO_H */
