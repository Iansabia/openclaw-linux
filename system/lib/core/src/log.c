/*
 * kelp-linux :: libkelp-core
 * log.c - Thread-safe logging
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/log.h>

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ---- module state ------------------------------------------------------- */

static struct {
    pthread_mutex_t mutex;
    FILE           *fp;
    const char     *name;
    int             level;
    int             initialised;
} g_log = {
    .mutex       = PTHREAD_MUTEX_INITIALIZER,
    .fp          = NULL,   /* NULL => stderr */
    .name        = "kelp",
    .level       = KELP_LOG_INFO,
    .initialised = 0,
};

/* ---- helpers ------------------------------------------------------------ */

static const char *level_label(int level)
{
    switch (level) {
    case KELP_LOG_TRACE: return "TRACE";
    case KELP_LOG_DEBUG: return "DEBUG";
    case KELP_LOG_INFO:  return "INFO ";
    case KELP_LOG_WARN:  return "WARN ";
    case KELP_LOG_ERROR: return "ERROR";
    case KELP_LOG_FATAL: return "FATAL";
    default:              return "?????";
    }
}

static void timestamp(char *buf, size_t cap)
{
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(buf, cap, "%Y-%m-%d %H:%M:%S", &tm);
}

/* ---- public API --------------------------------------------------------- */

void kelp_log_init(const char *name, int level)
{
    pthread_mutex_lock(&g_log.mutex);
    if (name)
        g_log.name = name;
    g_log.level       = level;
    g_log.initialised = 1;
    pthread_mutex_unlock(&g_log.mutex);
}

void kelp_log_set_level(int level)
{
    pthread_mutex_lock(&g_log.mutex);
    g_log.level = level;
    pthread_mutex_unlock(&g_log.mutex);
}

void kelp_log_set_file(FILE *fp)
{
    pthread_mutex_lock(&g_log.mutex);
    g_log.fp = fp;
    pthread_mutex_unlock(&g_log.mutex);
}

void kelp_log_write(int level, const char *file, int line,
                     const char *fmt, ...)
{
    pthread_mutex_lock(&g_log.mutex);

    if (level < g_log.level) {
        pthread_mutex_unlock(&g_log.mutex);
        return;
    }

    FILE *out = g_log.fp ? g_log.fp : stderr;

    /* Shorten the file path to just the basename for readability. */
    const char *base = file;
    if (file) {
        const char *slash = strrchr(file, '/');
        if (slash)
            base = slash + 1;
    }

    char ts[32];
    timestamp(ts, sizeof(ts));

    fprintf(out, "[%s] [%s] [%s:%d] ", ts, level_label(level), base, line);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    va_end(ap);

    fputc('\n', out);
    fflush(out);

    pthread_mutex_unlock(&g_log.mutex);
}
