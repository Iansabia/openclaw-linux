/*
 * kelp-linux :: libkelp-core
 * buf.h - Dynamic byte buffer
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_BUF_H
#define KELP_BUF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Dynamic byte buffer.
 *
 * `data` points to `cap` allocated bytes, of which the first `len` are valid.
 */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} kelp_buf_t;

/** Allocate a new buffer with `initial_cap` bytes of capacity. */
kelp_buf_t kelp_buf_new(size_t initial_cap);

/** Free all memory owned by the buffer and zero the struct. */
void kelp_buf_free(kelp_buf_t *b);

/** Append `len` bytes from `data` to the buffer, growing as needed. */
int kelp_buf_write(kelp_buf_t *b, const void *data, size_t len);

/**
 * Read the entire contents of `path` into the buffer.
 * Returns 0 on success, -1 on error.
 */
int kelp_buf_read_file(kelp_buf_t *b, const char *path);

/**
 * Write the buffer contents to `path`, creating or truncating the file.
 * Returns 0 on success, -1 on error.
 */
int kelp_buf_write_file(const kelp_buf_t *b, const char *path);

/** Reset the buffer length to zero without releasing memory. */
void kelp_buf_reset(kelp_buf_t *b);

#ifdef __cplusplus
}
#endif

#endif /* KELP_BUF_H */
