/*
 * clawd-linux :: libclawd-core
 * log.h - Thread-safe logging
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_LOG_H
#define CLAWD_LOG_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Log severity levels (numerically ordered). */
enum {
    CLAWD_LOG_TRACE = 0,
    CLAWD_LOG_DEBUG,
    CLAWD_LOG_INFO,
    CLAWD_LOG_WARN,
    CLAWD_LOG_ERROR,
    CLAWD_LOG_FATAL
};

/**
 * Initialise the logging subsystem.
 *
 * @param name   Application/subsystem name (printed in each line).
 * @param level  Minimum severity to emit (e.g. CLAWD_LOG_INFO).
 */
void clawd_log_init(const char *name, int level);

/** Change the minimum severity at runtime. */
void clawd_log_set_level(int level);

/**
 * Redirect log output to `fp`.
 * Pass NULL to revert to stderr (the default).
 */
void clawd_log_set_file(FILE *fp);

/**
 * Low-level write function -- prefer the macros below.
 */
void clawd_log_write(int level, const char *file, int line,
                     const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

/* ---- Convenience macros ------------------------------------------------- */

#define CLAWD_TRACE(fmt, ...) \
    clawd_log_write(CLAWD_LOG_TRACE, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define CLAWD_DEBUG(fmt, ...) \
    clawd_log_write(CLAWD_LOG_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define CLAWD_INFO(fmt, ...) \
    clawd_log_write(CLAWD_LOG_INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define CLAWD_WARN(fmt, ...) \
    clawd_log_write(CLAWD_LOG_WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define CLAWD_ERROR(fmt, ...) \
    clawd_log_write(CLAWD_LOG_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define CLAWD_FATAL(fmt, ...) \
    clawd_log_write(CLAWD_LOG_FATAL, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_LOG_H */
