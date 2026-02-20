/*
 * clawd-linux :: libclawd-memory
 * watcher.c - File system event watcher (inotify / kqueue)
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/watcher.h>
#include <clawd/log.h>

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

/* ----------------------------------------------------------------------- */
/* Platform-specific includes                                               */
/* ----------------------------------------------------------------------- */

#ifdef __linux__
#include <sys/inotify.h>
#include <limits.h>   /* NAME_MAX */
#endif

#ifdef __APPLE__
#include <sys/event.h>
#include <sys/time.h>
#include <fcntl.h>
#endif

/* ----------------------------------------------------------------------- */
/* Internal types                                                           */
/* ----------------------------------------------------------------------- */

/** A single watched path entry. */
typedef struct watch_entry {
    int                  wd;        /* watch descriptor (inotify) or fd (kqueue) */
    char                *path;
    clawd_watch_event_t  events;
    struct watch_entry  *next;
} watch_entry_t;

struct clawd_watcher {
    int              fd;            /* inotify fd or kqueue fd */
    watch_entry_t   *entries;       /* linked list of watches */
    int              n_watches;
    pthread_t        thread;
    volatile int     running;       /* 1 when event loop is active */
    int              pipe_fds[2];   /* self-pipe for waking the thread */
    clawd_watch_cb   cb;
    void            *userdata;
};

/* ----------------------------------------------------------------------- */
/* Forward declarations                                                     */
/* ----------------------------------------------------------------------- */

static void *watcher_thread_func(void *arg);
static int   watcher_add_single(clawd_watcher_t *w, const char *path,
                                 clawd_watch_event_t events);
static int   watcher_add_recursive(clawd_watcher_t *w, const char *path,
                                    clawd_watch_event_t events);
static watch_entry_t *watcher_find_by_wd(clawd_watcher_t *w, int wd);
static watch_entry_t *watcher_find_by_path(clawd_watcher_t *w,
                                            const char *path);
static char *watcher_strdup(const char *s);

/* ----------------------------------------------------------------------- */
/* Public API                                                               */
/* ----------------------------------------------------------------------- */

clawd_watcher_t *
clawd_watcher_new(void)
{
    clawd_watcher_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;

    w->pipe_fds[0] = -1;
    w->pipe_fds[1] = -1;

#ifdef __linux__
    w->fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (w->fd < 0) {
        CLAWD_ERROR("inotify_init1: %s", strerror(errno));
        free(w);
        return NULL;
    }
#elif defined(__APPLE__)
    w->fd = kqueue();
    if (w->fd < 0) {
        CLAWD_ERROR("kqueue: %s", strerror(errno));
        free(w);
        return NULL;
    }
#else
    CLAWD_ERROR("file watching not supported on this platform");
    free(w);
    return NULL;
#endif

    /* Create self-pipe for signalling the thread to stop. */
    if (pipe(w->pipe_fds) != 0) {
        CLAWD_ERROR("pipe: %s", strerror(errno));
        close(w->fd);
        free(w);
        return NULL;
    }

    return w;
}

void
clawd_watcher_free(clawd_watcher_t *w)
{
    if (!w) return;

    clawd_watcher_stop(w);

    /* Remove all watches. */
    watch_entry_t *e = w->entries;
    while (e) {
        watch_entry_t *next = e->next;
#ifdef __linux__
        if (w->fd >= 0 && e->wd >= 0) {
            inotify_rm_watch(w->fd, e->wd);
        }
#elif defined(__APPLE__)
        if (e->wd >= 0) {
            close(e->wd);
        }
#endif
        free(e->path);
        free(e);
        e = next;
    }

    if (w->fd >= 0) close(w->fd);
    if (w->pipe_fds[0] >= 0) close(w->pipe_fds[0]);
    if (w->pipe_fds[1] >= 0) close(w->pipe_fds[1]);

    free(w);
}

int
clawd_watcher_add(clawd_watcher_t *w, const char *path,
                   clawd_watch_event_t events, bool recursive)
{
    if (!w || !path) return -1;

    if (recursive) {
        return watcher_add_recursive(w, path, events);
    }
    return watcher_add_single(w, path, events);
}

int
clawd_watcher_remove(clawd_watcher_t *w, const char *path)
{
    if (!w || !path) return -1;

    watch_entry_t *prev = NULL;
    watch_entry_t *e    = w->entries;

    while (e) {
        if (strcmp(e->path, path) == 0) {
#ifdef __linux__
            if (w->fd >= 0 && e->wd >= 0) {
                inotify_rm_watch(w->fd, e->wd);
            }
#elif defined(__APPLE__)
            if (e->wd >= 0) {
                close(e->wd);
            }
#endif
            if (prev) prev->next = e->next;
            else      w->entries = e->next;

            free(e->path);
            free(e);
            w->n_watches--;
            return 0;
        }
        prev = e;
        e = e->next;
    }

    return -1;  /* not found */
}

int
clawd_watcher_start(clawd_watcher_t *w, clawd_watch_cb cb, void *userdata)
{
    if (!w || !cb) return -1;
    if (w->running) return -1;

    w->cb       = cb;
    w->userdata = userdata;
    w->running  = 1;

    int rc = pthread_create(&w->thread, NULL, watcher_thread_func, w);
    if (rc != 0) {
        CLAWD_ERROR("pthread_create: %s", strerror(rc));
        w->running = 0;
        return -1;
    }

    return 0;
}

void
clawd_watcher_stop(clawd_watcher_t *w)
{
    if (!w || !w->running) return;

    w->running = 0;

    /* Wake the thread by writing to the self-pipe. */
    if (w->pipe_fds[1] >= 0) {
        char byte = 'x';
        (void)write(w->pipe_fds[1], &byte, 1);
    }

    pthread_join(w->thread, NULL);
}

int
clawd_watcher_fd(clawd_watcher_t *w)
{
    if (!w) return -1;
    return w->fd;
}

/* ----------------------------------------------------------------------- */
/* Event loop thread                                                        */
/* ----------------------------------------------------------------------- */

#ifdef __linux__

static void *
watcher_thread_func(void *arg)
{
    clawd_watcher_t *w = arg;

    /* Buffer for inotify events. */
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));

    fd_set rfds;
    int maxfd = (w->fd > w->pipe_fds[0]) ? w->fd : w->pipe_fds[0];

    while (w->running) {
        FD_ZERO(&rfds);
        FD_SET(w->fd, &rfds);
        FD_SET(w->pipe_fds[0], &rfds);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ret == 0) continue;  /* timeout */

        /* Check self-pipe for stop signal. */
        if (FD_ISSET(w->pipe_fds[0], &rfds)) {
            break;
        }

        if (!FD_ISSET(w->fd, &rfds)) continue;

        ssize_t n = read(w->fd, buf, sizeof(buf));
        if (n <= 0) continue;

        const char *ptr = buf;
        while (ptr < buf + n) {
            const struct inotify_event *ev =
                (const struct inotify_event *)ptr;

            clawd_watch_event_t event = 0;
            if (ev->mask & IN_CREATE)     event |= CLAWD_WATCH_CREATE;
            if (ev->mask & IN_MODIFY)     event |= CLAWD_WATCH_MODIFY;
            if (ev->mask & IN_DELETE)     event |= CLAWD_WATCH_DELETE;
            if (ev->mask & IN_MOVED_FROM) event |= CLAWD_WATCH_MOVE;
            if (ev->mask & IN_MOVED_TO)   event |= CLAWD_WATCH_MOVE;

            if (event && w->cb) {
                /* Build full path. */
                watch_entry_t *we = watcher_find_by_wd(w, ev->wd);
                if (we) {
                    char fullpath[PATH_MAX];
                    if (ev->len > 0) {
                        snprintf(fullpath, sizeof(fullpath), "%s/%s",
                                 we->path, ev->name);
                    } else {
                        snprintf(fullpath, sizeof(fullpath), "%s", we->path);
                    }
                    w->cb(fullpath, event, w->userdata);
                }
            }

            ptr += sizeof(struct inotify_event) + ev->len;
        }
    }

    return NULL;
}

#elif defined(__APPLE__)

static void *
watcher_thread_func(void *arg)
{
    clawd_watcher_t *w = arg;

    /* Register the self-pipe for reading so we can break out. */
    struct kevent change;
    EV_SET(&change, (uintptr_t)w->pipe_fds[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
    kevent(w->fd, &change, 1, NULL, 0, NULL);

    struct kevent events[32];

    while (w->running) {
        struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
        int n = kevent(w->fd, NULL, 0, events, 32, &ts);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < n; i++) {
            /* Check for self-pipe signal. */
            if ((int)events[i].ident == w->pipe_fds[0]) {
                w->running = 0;
                break;
            }

            clawd_watch_event_t ev = 0;
            if (events[i].fflags & NOTE_WRITE)  ev |= CLAWD_WATCH_MODIFY;
            if (events[i].fflags & NOTE_DELETE)  ev |= CLAWD_WATCH_DELETE;
            if (events[i].fflags & NOTE_RENAME)  ev |= CLAWD_WATCH_MOVE;
            if (events[i].fflags & NOTE_EXTEND)  ev |= CLAWD_WATCH_MODIFY;
            /* NOTE: kqueue does not have a direct CREATE event on the
             * watched fd itself.  We treat NOTE_LINK as CREATE. */
            if (events[i].fflags & NOTE_LINK)    ev |= CLAWD_WATCH_CREATE;

            if (ev && w->cb) {
                watch_entry_t *we = watcher_find_by_wd(w, (int)events[i].ident);
                if (we) {
                    w->cb(we->path, ev, w->userdata);
                }
            }
        }
    }

    return NULL;
}

#else
/* Stub for unsupported platforms. */
static void *
watcher_thread_func(void *arg)
{
    (void)arg;
    return NULL;
}
#endif

/* ----------------------------------------------------------------------- */
/* Internal helpers                                                         */
/* ----------------------------------------------------------------------- */

static int
watcher_add_single(clawd_watcher_t *w, const char *path,
                    clawd_watch_event_t events)
{
    /* Check if already watching this path. */
    if (watcher_find_by_path(w, path)) return 0;

    int wd = -1;

#ifdef __linux__
    uint32_t mask = 0;
    if (events & CLAWD_WATCH_CREATE) mask |= IN_CREATE;
    if (events & CLAWD_WATCH_MODIFY) mask |= IN_MODIFY;
    if (events & CLAWD_WATCH_DELETE) mask |= IN_DELETE;
    if (events & CLAWD_WATCH_MOVE)   mask |= IN_MOVED_FROM | IN_MOVED_TO;

    wd = inotify_add_watch(w->fd, path, mask);
    if (wd < 0) {
        CLAWD_WARN("inotify_add_watch(%s): %s", path, strerror(errno));
        return -1;
    }

#elif defined(__APPLE__)
    wd = open(path, O_EVTONLY);
    if (wd < 0) {
        CLAWD_WARN("open(%s, O_EVTONLY): %s", path, strerror(errno));
        return -1;
    }

    unsigned int fflags = 0;
    if (events & CLAWD_WATCH_CREATE) fflags |= NOTE_LINK;
    if (events & CLAWD_WATCH_MODIFY) fflags |= NOTE_WRITE | NOTE_EXTEND;
    if (events & CLAWD_WATCH_DELETE) fflags |= NOTE_DELETE;
    if (events & CLAWD_WATCH_MOVE)   fflags |= NOTE_RENAME;

    struct kevent change;
    EV_SET(&change, (uintptr_t)wd, EVFILT_VNODE,
           EV_ADD | EV_CLEAR, fflags, 0, NULL);
    if (kevent(w->fd, &change, 1, NULL, 0, NULL) < 0) {
        CLAWD_WARN("kevent register(%s): %s", path, strerror(errno));
        close(wd);
        return -1;
    }
#else
    (void)events;
    CLAWD_ERROR("file watching not supported");
    return -1;
#endif

    /* Create the list entry. */
    watch_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry) {
#ifdef __linux__
        inotify_rm_watch(w->fd, wd);
#elif defined(__APPLE__)
        close(wd);
#endif
        return -1;
    }

    entry->wd     = wd;
    entry->path   = watcher_strdup(path);
    entry->events = events;
    entry->next   = w->entries;
    w->entries    = entry;
    w->n_watches++;

    return 0;
}

static int
watcher_add_recursive(clawd_watcher_t *w, const char *path,
                       clawd_watch_event_t events)
{
    /* Add the directory itself. */
    int rc = watcher_add_single(w, path, events);
    if (rc != 0) return rc;

    /* Enumerate subdirectories. */
    DIR *dir = opendir(path);
    if (!dir) return 0;  /* not a directory, that's fine */

    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (de->d_name[0] == '.' &&
            (de->d_name[1] == '\0' ||
             (de->d_name[1] == '.' && de->d_name[2] == '\0'))) {
            continue;
        }

        char child[4096];
        snprintf(child, sizeof(child), "%s/%s", path, de->d_name);

        struct stat st;
        if (stat(child, &st) == 0 && S_ISDIR(st.st_mode)) {
            watcher_add_recursive(w, child, events);
        }
    }

    closedir(dir);
    return 0;
}

static watch_entry_t *
watcher_find_by_wd(clawd_watcher_t *w, int wd)
{
    for (watch_entry_t *e = w->entries; e; e = e->next) {
        if (e->wd == wd) return e;
    }
    return NULL;
}

static watch_entry_t *
watcher_find_by_path(clawd_watcher_t *w, const char *path)
{
    for (watch_entry_t *e = w->entries; e; e = e->next) {
        if (strcmp(e->path, path) == 0) return e;
    }
    return NULL;
}

static char *
watcher_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s);
    char *d = malloc(len + 1);
    if (d) memcpy(d, s, len + 1);
    return d;
}
