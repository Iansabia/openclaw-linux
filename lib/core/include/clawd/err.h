/*
 * clawd-linux :: libclawd-core
 * err.h - Structured error handling
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_ERR_H
#define CLAWD_ERR_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Standard error codes. */
enum {
    CLAWD_OK            = 0,
    CLAWD_ERR_NOMEM,
    CLAWD_ERR_IO,
    CLAWD_ERR_PARSE,
    CLAWD_ERR_NET,
    CLAWD_ERR_AUTH,
    CLAWD_ERR_TIMEOUT,
    CLAWD_ERR_NOTFOUND,
    CLAWD_ERR_INVALID,
    CLAWD_ERR_INTERNAL
};

/** Lightweight error value. */
typedef struct {
    int  code;
    char message[256];
} clawd_err_t;

/** Populate an error struct with a printf-style message. */
void clawd_err_set(clawd_err_t *e, int code, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/** Return true when the error represents success. */
bool clawd_err_ok(const clawd_err_t *e);

/** Return a human-readable label for an error code. */
const char *clawd_err_string(int code);

/**
 * CLAWD_CHECK -- evaluate `expr`; if it is false, set the error and return
 * the given code from the enclosing function.
 *
 * Usage:
 *     CLAWD_CHECK(ptr != NULL, &err, CLAWD_ERR_NOMEM, "allocation failed");
 */
#define CLAWD_CHECK(expr, err, code, fmt, ...)                                \
    do {                                                                      \
        if (!(expr)) {                                                        \
            clawd_err_set((err), (code), fmt, ##__VA_ARGS__);                 \
            return (code);                                                    \
        }                                                                     \
    } while (0)

/**
 * CLAWD_ASSERT -- fatal assertion.  Prints the message and aborts.
 */
#define CLAWD_ASSERT(expr, fmt, ...)                                          \
    do {                                                                      \
        if (!(expr)) {                                                        \
            fprintf(stderr, "FATAL ASSERT [%s:%d] " fmt "\n",                \
                    __FILE__, __LINE__, ##__VA_ARGS__);                        \
            abort();                                                          \
        }                                                                     \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_ERR_H */
