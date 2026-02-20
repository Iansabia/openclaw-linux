/*
 * clawd-linux :: libclawd-net
 * heartbeat.c - Periodic health-check / heartbeat
 *
 * Spawns a background pthread that sends periodic HTTP GET requests
 * to a health-check URL and records whether the endpoint is alive.
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/heartbeat.h>
#include <clawd/http.h>
#include <clawd/err.h>
#include <clawd/log.h>

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ---- Background worker -------------------------------------------------- */

/**
 * Perform a single health-check GET request.
 * Returns true if the endpoint responded with 2xx within a reasonable timeout.
 */
static bool do_ping(const char *url)
{
    clawd_http_request_t req = {
        .method           = "GET",
        .url              = url,
        .headers          = NULL,
        .body             = NULL,
        .body_len         = 0,
        .timeout_ms       = 5000,
        .follow_redirects = true,
        .ca_bundle        = NULL
    };

    clawd_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    int rc = clawd_http_request(&req, &resp);
    bool alive = (rc == CLAWD_OK && resp.status_code >= 200 &&
                  resp.status_code < 300);

    clawd_http_response_free(&resp);
    return alive;
}

/**
 * Sleep for `seconds` while checking the running flag every 500ms
 * so we can exit promptly when stopped.
 */
static void interruptible_sleep(const clawd_heartbeat_t *hb, int seconds)
{
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 500000000L }; /* 500ms */
    int iterations = seconds * 2;

    for (int i = 0; i < iterations; i++) {
        if (!atomic_load(&hb->running))
            return;
        nanosleep(&ts, NULL);
    }
}

static void *heartbeat_thread(void *arg)
{
    clawd_heartbeat_t *hb = (clawd_heartbeat_t *)arg;

    CLAWD_INFO("heartbeat: started (url=%s, interval=%ds)",
               hb->url, hb->interval_sec);

    while (atomic_load(&hb->running)) {
        bool alive = do_ping(hb->url);
        bool was_alive = atomic_exchange(&hb->alive, alive);

        if (alive && !was_alive) {
            CLAWD_INFO("heartbeat: endpoint is now UP: %s", hb->url);
        } else if (!alive && was_alive) {
            CLAWD_WARN("heartbeat: endpoint is now DOWN: %s", hb->url);
        }

        CLAWD_TRACE("heartbeat: ping %s -> %s", hb->url,
                     alive ? "alive" : "dead");

        interruptible_sleep(hb, hb->interval_sec);
    }

    CLAWD_INFO("heartbeat: thread exiting for %s", hb->url);
    return NULL;
}

/* ---- Public API --------------------------------------------------------- */

int clawd_heartbeat_start(clawd_heartbeat_t *hb,
                          const char *url, int interval_sec)
{
    if (!hb || !url || interval_sec < 1) {
        CLAWD_ERROR("heartbeat: invalid arguments");
        return -1;
    }

    memset(hb, 0, sizeof(*hb));
    pthread_mutex_init(&hb->mutex, NULL);

    hb->url = strdup(url);
    if (!hb->url) {
        CLAWD_ERROR("heartbeat: allocation failed");
        return -1;
    }

    hb->interval_sec = interval_sec;
    atomic_store(&hb->alive, false);
    atomic_store(&hb->running, true);

    int rc = pthread_create(&hb->thread, NULL, heartbeat_thread, hb);
    if (rc != 0) {
        CLAWD_ERROR("heartbeat: pthread_create failed (rc=%d)", rc);
        free(hb->url);
        hb->url = NULL;
        atomic_store(&hb->running, false);
        return -1;
    }

    return 0;
}

void clawd_heartbeat_stop(clawd_heartbeat_t *hb)
{
    if (!hb)
        return;

    pthread_mutex_lock(&hb->mutex);

    if (!atomic_load(&hb->running)) {
        pthread_mutex_unlock(&hb->mutex);
        return;
    }

    atomic_store(&hb->running, false);
    pthread_mutex_unlock(&hb->mutex);

    pthread_join(hb->thread, NULL);

    free(hb->url);
    hb->url = NULL;
    pthread_mutex_destroy(&hb->mutex);

    CLAWD_DEBUG("heartbeat: stopped");
}

bool clawd_heartbeat_is_alive(const clawd_heartbeat_t *hb)
{
    if (!hb)
        return false;
    return atomic_load(&hb->alive);
}
