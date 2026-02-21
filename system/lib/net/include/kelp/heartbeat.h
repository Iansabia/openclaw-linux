/*
 * kelp-linux :: libkelp-net
 * heartbeat.h - Periodic health-check / heartbeat
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_HEARTBEAT_H
#define KELP_HEARTBEAT_H

#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Heartbeat state.
 *
 * Sends periodic HTTP GET requests to a health-check URL and tracks
 * whether the remote endpoint is alive.
 */
typedef struct kelp_heartbeat {
    char           *url;            /* health-check URL (owned) */
    int             interval_sec;   /* seconds between pings */
    atomic_bool     alive;          /* last-known liveness */
    atomic_bool     running;        /* thread control flag */
    pthread_t       thread;         /* background worker */
    pthread_mutex_t mutex;          /* protects startup/shutdown */
} kelp_heartbeat_t;

/**
 * Start a heartbeat worker that pings `url` every `interval_sec` seconds.
 *
 * @param hb            Pointer to a caller-allocated heartbeat struct.
 * @param url           URL to GET for health checking.
 * @param interval_sec  Seconds between pings (minimum 1).
 * @return 0 on success, -1 on error.
 */
int kelp_heartbeat_start(kelp_heartbeat_t *hb,
                          const char *url, int interval_sec);

/**
 * Stop the heartbeat worker and release resources.
 * Safe to call even if the heartbeat was never started.
 */
void kelp_heartbeat_stop(kelp_heartbeat_t *hb);

/**
 * Return the last-known liveness state.
 * Returns true if the most recent health check succeeded.
 */
bool kelp_heartbeat_is_alive(const kelp_heartbeat_t *hb);

#ifdef __cplusplus
}
#endif

#endif /* KELP_HEARTBEAT_H */
