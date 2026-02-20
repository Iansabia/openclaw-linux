/*
 * clawd-linux :: libclawd-terminal
 * progress.c - Progress bar and spinner implementations
 *
 * The progress bar renders as:  [=====>    ]  50%
 * The spinner uses Braille animation: ⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/progress.h>
#include <clawd/ansi.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- Progress bar ------------------------------------------------------- */

struct clawd_progress {
    FILE *fp;
    int   total;
    int   current;
    int   width;
    bool  finished;
};

clawd_progress_t *clawd_progress_new(FILE *fp, int total, int width)
{
    if (!fp || total <= 0 || width <= 0) return NULL;

    clawd_progress_t *p = (clawd_progress_t *)calloc(1, sizeof(*p));
    if (!p) return NULL;

    p->fp       = fp;
    p->total    = total;
    p->current  = 0;
    p->width    = width;
    p->finished = false;

    return p;
}

void clawd_progress_free(clawd_progress_t *p)
{
    free(p);
}

void clawd_progress_update(clawd_progress_t *p, int current)
{
    if (!p || p->finished) return;

    if (current < 0) current = 0;
    if (current > p->total) current = p->total;
    p->current = current;

    double ratio = (double)current / (double)p->total;
    int filled = (int)(ratio * p->width);
    int pct    = (int)(ratio * 100.0);

    /* Move to beginning of line */
    fprintf(p->fp, "\r[");

    for (int i = 0; i < p->width; i++) {
        if (i < filled) {
            fputc('=', p->fp);
        } else if (i == filled) {
            fputc('>', p->fp);
        } else {
            fputc(' ', p->fp);
        }
    }

    fprintf(p->fp, "] %3d%%", pct);
    fflush(p->fp);
}

void clawd_progress_finish(clawd_progress_t *p)
{
    if (!p || p->finished) return;

    p->finished = true;
    p->current  = p->total;

    /* Render full bar */
    fprintf(p->fp, "\r[");
    for (int i = 0; i < p->width; i++) {
        fputc('=', p->fp);
    }
    fprintf(p->fp, "] 100%%\n");
    fflush(p->fp);
}

/* ---- Spinner ------------------------------------------------------------ */

/* Braille spinner frames (UTF-8 encoded) */
static const char *spinner_frames[] = {
    "\xe2\xa0\x8b",  /* ⠋ */
    "\xe2\xa0\x99",  /* ⠙ */
    "\xe2\xa0\xb9",  /* ⠹ */
    "\xe2\xa0\xb8",  /* ⠸ */
    "\xe2\xa0\xbc",  /* ⠼ */
    "\xe2\xa0\xb4",  /* ⠴ */
    "\xe2\xa0\xa6",  /* ⠦ */
    "\xe2\xa0\xa7",  /* ⠧ */
    "\xe2\xa0\x87",  /* ⠇ */
    "\xe2\xa0\x8f",  /* ⠏ */
};
static const int spinner_frame_count = 10;

struct clawd_spinner {
    FILE      *fp;
    char      *message;
    pthread_t  thread;
    pthread_mutex_t mutex;
    bool       running;
    bool       thread_started;
    int        frame;
};

static void *spinner_thread_func(void *arg)
{
    clawd_spinner_t *s = (clawd_spinner_t *)arg;

    while (1) {
        pthread_mutex_lock(&s->mutex);
        bool running = s->running;
        int frame = s->frame;
        const char *msg = s->message ? s->message : "";
        /* Make a local copy so we can unlock before fprintf */
        size_t mlen = strlen(msg);
        char *local_msg = (char *)malloc(mlen + 1);
        if (local_msg) {
            memcpy(local_msg, msg, mlen + 1);
        }
        s->frame = (frame + 1) % spinner_frame_count;
        pthread_mutex_unlock(&s->mutex);

        if (!running) {
            free(local_msg);
            break;
        }

        /* Clear line and render spinner frame + message */
        fprintf(s->fp, "\r\033[2K%s %s",
                spinner_frames[frame],
                local_msg ? local_msg : "");
        fflush(s->fp);
        free(local_msg);

        /* ~80ms between frames */
        usleep(80000);
    }

    return NULL;
}

clawd_spinner_t *clawd_spinner_new(FILE *fp, const char *message)
{
    if (!fp) return NULL;

    clawd_spinner_t *s = (clawd_spinner_t *)calloc(1, sizeof(*s));
    if (!s) return NULL;

    s->fp = fp;
    s->message = message ? strdup(message) : strdup("");
    s->running = false;
    s->thread_started = false;
    s->frame = 0;
    pthread_mutex_init(&s->mutex, NULL);

    return s;
}

void clawd_spinner_free(clawd_spinner_t *s)
{
    if (!s) return;

    if (s->running) {
        clawd_spinner_stop(s, NULL);
    }

    pthread_mutex_destroy(&s->mutex);
    free(s->message);
    free(s);
}

void clawd_spinner_start(clawd_spinner_t *s)
{
    if (!s || s->running) return;

    pthread_mutex_lock(&s->mutex);
    s->running = true;
    s->frame   = 0;
    pthread_mutex_unlock(&s->mutex);

    if (pthread_create(&s->thread, NULL, spinner_thread_func, s) != 0) {
        s->running = false;
        return;
    }
    s->thread_started = true;
}

void clawd_spinner_stop(clawd_spinner_t *s, const char *final_message)
{
    if (!s || !s->running) return;

    pthread_mutex_lock(&s->mutex);
    s->running = false;
    pthread_mutex_unlock(&s->mutex);

    if (s->thread_started) {
        pthread_join(s->thread, NULL);
        s->thread_started = false;
    }

    /* Clear the spinner line and optionally print the final message */
    fprintf(s->fp, "\r\033[2K");
    if (final_message && *final_message) {
        fprintf(s->fp, "%s\n", final_message);
    }
    fflush(s->fp);
}

void clawd_spinner_set_message(clawd_spinner_t *s, const char *msg)
{
    if (!s) return;

    pthread_mutex_lock(&s->mutex);
    free(s->message);
    s->message = msg ? strdup(msg) : strdup("");
    pthread_mutex_unlock(&s->mutex);
}
