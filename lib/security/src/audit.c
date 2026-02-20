/*
 * clawd-linux :: libclawd-security
 * audit.c - Audit engine implementation
 *
 * Thread-safe audit logging.  Events are serialised as JSON Lines and written
 * to a log file.  Additional callback sinks may be registered.
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/audit.h>
#include <clawd/log.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- limits ------------------------------------------------------------- */

#define AUDIT_MAX_SINKS 16

/* ---- internal types ----------------------------------------------------- */

typedef struct {
    clawd_audit_sink_t fn;
    void              *userdata;
} sink_entry_t;

/* ---- module state ------------------------------------------------------- */

static struct {
    pthread_mutex_t     mutex;
    FILE               *fp;
    int                 initialised;
    clawd_audit_level_t min_level;
    sink_entry_t        sinks[AUDIT_MAX_SINKS];
    int                 sink_count;
} g_audit = {
    .mutex       = PTHREAD_MUTEX_INITIALIZER,
    .fp          = NULL,
    .initialised = 0,
    .min_level   = CLAWD_AUDIT_INFO,
    .sink_count  = 0,
};

/* ---- helpers ------------------------------------------------------------ */

static const char *level_string(clawd_audit_level_t level)
{
    switch (level) {
    case CLAWD_AUDIT_INFO:      return "info";
    case CLAWD_AUDIT_WARN:      return "warn";
    case CLAWD_AUDIT_ALERT:     return "alert";
    case CLAWD_AUDIT_VIOLATION: return "violation";
    default:                    return "unknown";
    }
}

/**
 * Escape a string for inclusion in a JSON value.
 *
 * Writes the escaped string (without surrounding quotes) into @p out.
 * Returns the number of characters written (excluding NUL), or -1 if
 * the buffer is too small.
 */
static int json_escape(const char *src, char *out, size_t out_len)
{
    if (!src) {
        if (out_len > 0) out[0] = '\0';
        return 0;
    }

    size_t pos = 0;
    for (const char *p = src; *p; p++) {
        char esc = 0;
        switch (*p) {
        case '"':  esc = '"';  break;
        case '\\': esc = '\\'; break;
        case '\b': esc = 'b';  break;
        case '\f': esc = 'f';  break;
        case '\n': esc = 'n';  break;
        case '\r': esc = 'r';  break;
        case '\t': esc = 't';  break;
        default:   break;
        }

        if (esc) {
            if (pos + 2 >= out_len) return -1;
            out[pos++] = '\\';
            out[pos++] = esc;
        } else {
            if (pos + 1 >= out_len) return -1;
            out[pos++] = *p;
        }
    }

    if (pos >= out_len) return -1;
    out[pos] = '\0';
    return (int)pos;
}

static void format_timestamp(time_t t, char *buf, size_t cap)
{
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(buf, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* ---- public API --------------------------------------------------------- */

int clawd_audit_init(const char *log_path)
{
    if (!log_path)
        return -1;

    pthread_mutex_lock(&g_audit.mutex);

    if (g_audit.initialised && g_audit.fp) {
        fclose(g_audit.fp);
        g_audit.fp = NULL;
    }

    g_audit.fp = fopen(log_path, "a");
    if (!g_audit.fp) {
        pthread_mutex_unlock(&g_audit.mutex);
        CLAWD_ERROR("audit: cannot open log file: %s", log_path);
        return -1;
    }

    g_audit.initialised = 1;
    g_audit.min_level   = CLAWD_AUDIT_INFO;
    g_audit.sink_count  = 0;

    pthread_mutex_unlock(&g_audit.mutex);

    CLAWD_INFO("audit: initialised, log_path=%s", log_path);
    return 0;
}

void clawd_audit_shutdown(void)
{
    pthread_mutex_lock(&g_audit.mutex);

    if (g_audit.fp) {
        fflush(g_audit.fp);
        fclose(g_audit.fp);
        g_audit.fp = NULL;
    }

    g_audit.initialised = 0;
    g_audit.sink_count  = 0;

    pthread_mutex_unlock(&g_audit.mutex);

    CLAWD_INFO("audit: shut down");
}

void clawd_audit_log(const clawd_audit_event_t *event)
{
    if (!event)
        return;

    pthread_mutex_lock(&g_audit.mutex);

    if (!g_audit.initialised) {
        pthread_mutex_unlock(&g_audit.mutex);
        return;
    }

    /* Filter by minimum level. */
    if ((int)event->level < (int)g_audit.min_level) {
        pthread_mutex_unlock(&g_audit.mutex);
        return;
    }

    /* ---- Format JSON line ---- */

    char ts[64];
    format_timestamp(event->timestamp ? event->timestamp : time(NULL),
                     ts, sizeof(ts));

    /* Escape string fields. */
    char cat_esc[256]     = "";
    char action_esc[256]  = "";
    char subject_esc[512] = "";
    char object_esc[1024] = "";
    char detail_esc[2048] = "";

    json_escape(event->category, cat_esc,     sizeof(cat_esc));
    json_escape(event->action,   action_esc,  sizeof(action_esc));
    json_escape(event->subject,  subject_esc, sizeof(subject_esc));
    json_escape(event->object,   object_esc,  sizeof(object_esc));
    json_escape(event->detail,   detail_esc,  sizeof(detail_esc));

    if (g_audit.fp) {
        fprintf(g_audit.fp,
                "{\"timestamp\":\"%s\","
                "\"level\":\"%s\","
                "\"category\":\"%s\","
                "\"action\":\"%s\","
                "\"subject\":\"%s\","
                "\"object\":\"%s\","
                "\"detail\":\"%s\","
                "\"allowed\":%s}\n",
                ts,
                level_string(event->level),
                cat_esc,
                action_esc,
                subject_esc,
                object_esc,
                detail_esc,
                event->allowed ? "true" : "false");
        fflush(g_audit.fp);
    }

    /* ---- Dispatch to registered sinks ---- */

    for (int i = 0; i < g_audit.sink_count; i++) {
        if (g_audit.sinks[i].fn) {
            g_audit.sinks[i].fn(event, g_audit.sinks[i].userdata);
        }
    }

    pthread_mutex_unlock(&g_audit.mutex);
}

int clawd_audit_add_sink(clawd_audit_sink_t sink, void *userdata)
{
    if (!sink)
        return -1;

    pthread_mutex_lock(&g_audit.mutex);

    if (g_audit.sink_count >= AUDIT_MAX_SINKS) {
        pthread_mutex_unlock(&g_audit.mutex);
        CLAWD_WARN("audit: maximum number of sinks reached (%d)",
                   AUDIT_MAX_SINKS);
        return -1;
    }

    g_audit.sinks[g_audit.sink_count].fn       = sink;
    g_audit.sinks[g_audit.sink_count].userdata  = userdata;
    g_audit.sink_count++;

    pthread_mutex_unlock(&g_audit.mutex);
    return 0;
}

void clawd_audit_set_min_level(clawd_audit_level_t level)
{
    pthread_mutex_lock(&g_audit.mutex);
    g_audit.min_level = level;
    pthread_mutex_unlock(&g_audit.mutex);
}
