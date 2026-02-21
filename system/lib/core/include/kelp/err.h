/*
 * kelp-linux :: libkelp-core
 * err.h - Structured error handling
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_ERR_H
#define KELP_ERR_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Standard error codes. */
enum {
    KELP_OK            = 0,
    KELP_ERR_NOMEM,
    KELP_ERR_IO,
    KELP_ERR_PARSE,
    KELP_ERR_NET,
    KELP_ERR_AUTH,
    KELP_ERR_TIMEOUT,
    KELP_ERR_NOTFOUND,
    KELP_ERR_INVALID,
    KELP_ERR_INTERNAL
};

/** Lightweight error value. */
typedef struct {
    int  code;
    char message[256];
} kelp_err_t;

/** Populate an error struct with a printf-style message. */
void kelp_err_set(kelp_err_t *e, int code, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/** Return true when the error represents success. */
bool kelp_err_ok(const kelp_err_t *e);

/** Return a human-readable label for an error code. */
const char *kelp_err_string(int code);

/**
 * KELP_CHECK -- evaluate `expr`; if it is false, set the error and return
 * the given code from the enclosing function.
 *
 * Usage:
 *     KELP_CHECK(ptr != NULL, &err, KELP_ERR_NOMEM, "allocation failed");
 */
#define KELP_CHECK(expr, err, code, fmt, ...)                                \
    do {                                                                      \
        if (!(expr)) {                                                        \
            kelp_err_set((err), (code), fmt, ##__VA_ARGS__);                 \
            return (code);                                                    \
        }                                                                     \
    } while (0)

/**
 * KELP_ASSERT -- fatal assertion.  Prints the message and aborts.
 */
#define KELP_ASSERT(expr, fmt, ...)                                          \
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

#endif /* KELP_ERR_H */
