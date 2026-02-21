/*
 * kelp-linux :: libkelp-core
 * log.h - Thread-safe logging
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_LOG_H
#define KELP_LOG_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Log severity levels (numerically ordered). */
enum {
    KELP_LOG_TRACE = 0,
    KELP_LOG_DEBUG,
    KELP_LOG_INFO,
    KELP_LOG_WARN,
    KELP_LOG_ERROR,
    KELP_LOG_FATAL
};

/**
 * Initialise the logging subsystem.
 *
 * @param name   Application/subsystem name (printed in each line).
 * @param level  Minimum severity to emit (e.g. KELP_LOG_INFO).
 */
void kelp_log_init(const char *name, int level);

/** Change the minimum severity at runtime. */
void kelp_log_set_level(int level);

/**
 * Redirect log output to `fp`.
 * Pass NULL to revert to stderr (the default).
 */
void kelp_log_set_file(FILE *fp);

/**
 * Low-level write function -- prefer the macros below.
 */
void kelp_log_write(int level, const char *file, int line,
                     const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

/* ---- Convenience macros ------------------------------------------------- */

#define KELP_TRACE(fmt, ...) \
    kelp_log_write(KELP_LOG_TRACE, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define KELP_DEBUG(fmt, ...) \
    kelp_log_write(KELP_LOG_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define KELP_INFO(fmt, ...) \
    kelp_log_write(KELP_LOG_INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define KELP_WARN(fmt, ...) \
    kelp_log_write(KELP_LOG_WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define KELP_ERROR(fmt, ...) \
    kelp_log_write(KELP_LOG_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define KELP_FATAL(fmt, ...) \
    kelp_log_write(KELP_LOG_FATAL, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* KELP_LOG_H */
