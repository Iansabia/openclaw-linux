/*
 * kelp-linux :: libkelp-memory
 * watcher.h - File system event watcher (inotify / kqueue)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_WATCHER_H
#define KELP_WATCHER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Bitmask of file system events to watch. */
typedef enum {
    KELP_WATCH_CREATE = 1,
    KELP_WATCH_MODIFY = 2,
    KELP_WATCH_DELETE = 4,
    KELP_WATCH_MOVE   = 8,
    KELP_WATCH_ALL    = 15
} kelp_watch_event_t;

/**
 * Callback invoked when a watched event fires.
 *
 * @param path      Absolute path of the affected file.
 * @param event     The event type.
 * @param userdata  Opaque pointer passed to kelp_watcher_start().
 */
typedef void (*kelp_watch_cb)(const char *path,
                                kelp_watch_event_t event,
                                void *userdata);

/** Opaque file watcher handle. */
typedef struct kelp_watcher kelp_watcher_t;

/**
 * Create a new file watcher.
 *
 * @return Handle on success, NULL on failure.
 */
kelp_watcher_t *kelp_watcher_new(void);

/**
 * Free the watcher and all associated resources.
 * Implicitly calls kelp_watcher_stop() if running.
 */
void kelp_watcher_free(kelp_watcher_t *w);

/**
 * Add a path to the watch set.
 *
 * @param w          Watcher handle.
 * @param path       Directory or file to watch.
 * @param events     Bitmask of events to watch for.
 * @param recursive  If true and path is a directory, watch all
 *                   subdirectories recursively.
 * @return 0 on success, -1 on error.
 */
int kelp_watcher_add(kelp_watcher_t *w, const char *path,
                       kelp_watch_event_t events, bool recursive);

/**
 * Remove a path from the watch set.
 *
 * @return 0 on success, -1 if the path was not being watched.
 */
int kelp_watcher_remove(kelp_watcher_t *w, const char *path);

/**
 * Start the watcher event loop in a background thread.
 *
 * @param w         Watcher handle.
 * @param cb        Callback for events.
 * @param userdata  Opaque pointer forwarded to the callback.
 * @return 0 on success, -1 on error.
 */
int kelp_watcher_start(kelp_watcher_t *w, kelp_watch_cb cb,
                         void *userdata);

/**
 * Stop the watcher event loop and join the background thread.
 */
void kelp_watcher_stop(kelp_watcher_t *w);

/**
 * Return the underlying file descriptor (inotify fd or kqueue fd)
 * for integration with an external event loop (epoll/kqueue).
 *
 * @return fd >= 0 on success, -1 if not initialised.
 */
int kelp_watcher_fd(kelp_watcher_t *w);

#ifdef __cplusplus
}
#endif

#endif /* KELP_WATCHER_H */
