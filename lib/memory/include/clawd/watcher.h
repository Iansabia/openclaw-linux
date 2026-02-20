/*
 * clawd-linux :: libclawd-memory
 * watcher.h - File system event watcher (inotify / kqueue)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_WATCHER_H
#define CLAWD_WATCHER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Bitmask of file system events to watch. */
typedef enum {
    CLAWD_WATCH_CREATE = 1,
    CLAWD_WATCH_MODIFY = 2,
    CLAWD_WATCH_DELETE = 4,
    CLAWD_WATCH_MOVE   = 8,
    CLAWD_WATCH_ALL    = 15
} clawd_watch_event_t;

/**
 * Callback invoked when a watched event fires.
 *
 * @param path      Absolute path of the affected file.
 * @param event     The event type.
 * @param userdata  Opaque pointer passed to clawd_watcher_start().
 */
typedef void (*clawd_watch_cb)(const char *path,
                                clawd_watch_event_t event,
                                void *userdata);

/** Opaque file watcher handle. */
typedef struct clawd_watcher clawd_watcher_t;

/**
 * Create a new file watcher.
 *
 * @return Handle on success, NULL on failure.
 */
clawd_watcher_t *clawd_watcher_new(void);

/**
 * Free the watcher and all associated resources.
 * Implicitly calls clawd_watcher_stop() if running.
 */
void clawd_watcher_free(clawd_watcher_t *w);

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
int clawd_watcher_add(clawd_watcher_t *w, const char *path,
                       clawd_watch_event_t events, bool recursive);

/**
 * Remove a path from the watch set.
 *
 * @return 0 on success, -1 if the path was not being watched.
 */
int clawd_watcher_remove(clawd_watcher_t *w, const char *path);

/**
 * Start the watcher event loop in a background thread.
 *
 * @param w         Watcher handle.
 * @param cb        Callback for events.
 * @param userdata  Opaque pointer forwarded to the callback.
 * @return 0 on success, -1 on error.
 */
int clawd_watcher_start(clawd_watcher_t *w, clawd_watch_cb cb,
                         void *userdata);

/**
 * Stop the watcher event loop and join the background thread.
 */
void clawd_watcher_stop(clawd_watcher_t *w);

/**
 * Return the underlying file descriptor (inotify fd or kqueue fd)
 * for integration with an external event loop (epoll/kqueue).
 *
 * @return fd >= 0 on success, -1 if not initialised.
 */
int clawd_watcher_fd(clawd_watcher_t *w);

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_WATCHER_H */
