/*
 * kelp-linux :: libkelp-security
 * audit.h - Audit engine
 *
 * Thread-safe audit logging with multiple sink support.  Events are written
 * as JSON Lines to a file and optionally dispatched to registered callbacks.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_AUDIT_H
#define KELP_AUDIT_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Severity levels for audit events (numerically ordered). */
typedef enum {
    KELP_AUDIT_INFO      = 0,
    KELP_AUDIT_WARN      = 1,
    KELP_AUDIT_ALERT     = 2,
    KELP_AUDIT_VIOLATION = 3
} kelp_audit_level_t;

/**
 * A single audit event.
 *
 * All string pointers must remain valid for the lifetime of the event (they
 * are NOT copied internally -- the caller owns the memory).
 */
typedef struct kelp_audit_event {
    kelp_audit_level_t  level;
    time_t               timestamp;
    const char          *category;    /* "fs", "net", "exec", "auth", "tool" */
    const char          *action;      /* "read", "write", "exec", "connect"  */
    const char          *subject;     /* who (user, agent, session id)       */
    const char          *object;      /* what (path, url, command)           */
    const char          *detail;      /* additional detail (may be NULL)     */
    bool                 allowed;
} kelp_audit_event_t;

/**
 * Callback type for audit sinks.
 *
 * @param event     The event being logged.
 * @param userdata  Opaque pointer supplied at registration time.
 */
typedef void (*kelp_audit_sink_t)(const kelp_audit_event_t *event,
                                   void *userdata);

/**
 * Initialise the audit subsystem.
 *
 * Opens (or creates) the log file at @p log_path in append mode.
 * Must be called before any other audit function.
 *
 * @param log_path  Path to the JSON-Lines audit log file.
 * @return 0 on success, -1 on error (e.g. cannot open file).
 */
int kelp_audit_init(const char *log_path);

/**
 * Shut down the audit subsystem.
 *
 * Flushes and closes the log file, clears all registered sinks.
 */
void kelp_audit_shutdown(void);

/**
 * Log an audit event.
 *
 * The event is serialised to JSON and written to the log file.  It is also
 * dispatched to every registered sink whose minimum level is met.
 *
 * If the event level is below the current minimum level it is silently
 * discarded.
 *
 * @param event  The event to log (must not be NULL).
 */
void kelp_audit_log(const kelp_audit_event_t *event);

/**
 * Register an additional audit sink (callback).
 *
 * @param sink      Callback function.
 * @param userdata  Opaque pointer passed to @p sink on each invocation.
 * @return 0 on success, -1 on error (e.g. too many sinks).
 */
int kelp_audit_add_sink(kelp_audit_sink_t sink, void *userdata);

/**
 * Set the minimum severity level for audit events.
 *
 * Events below this level are silently discarded by kelp_audit_log().
 *
 * @param level  The new minimum level.
 */
void kelp_audit_set_min_level(kelp_audit_level_t level);

#ifdef __cplusplus
}
#endif

#endif /* KELP_AUDIT_H */
