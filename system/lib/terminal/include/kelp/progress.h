/*
 * kelp-linux :: libkelp-terminal
 * progress.h - Progress bars and spinners
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_PROGRESS_H
#define KELP_PROGRESS_H

#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Opaque handles ----------------------------------------------------- */

typedef struct kelp_progress kelp_progress_t;
typedef struct kelp_spinner  kelp_spinner_t;

/* ---- Progress bar API --------------------------------------------------- */

/**
 * Create a new progress bar.
 *
 * @param fp     Output stream (must be a TTY for dynamic updates).
 * @param total  Total number of steps (must be > 0).
 * @param width  Display width of the bar in characters (e.g. 40).
 * @return Progress bar handle, or NULL on allocation failure.
 */
kelp_progress_t *kelp_progress_new(FILE *fp, int total, int width);

/**
 * Free a progress bar.
 *
 * @param p  Progress bar handle (may be NULL).
 */
void kelp_progress_free(kelp_progress_t *p);

/**
 * Update the progress bar to reflect the current step.
 *
 * @param p        Progress bar handle.
 * @param current  Current step (0 .. total).
 */
void kelp_progress_update(kelp_progress_t *p, int current);

/**
 * Mark the progress bar as finished and move to a new line.
 *
 * @param p  Progress bar handle.
 */
void kelp_progress_finish(kelp_progress_t *p);

/* ---- Spinner API -------------------------------------------------------- */

/**
 * Create a new spinner.
 *
 * @param fp       Output stream.
 * @param message  Initial message displayed beside the spinner.
 * @return Spinner handle, or NULL on allocation failure.
 */
kelp_spinner_t *kelp_spinner_new(FILE *fp, const char *message);

/**
 * Free a spinner. Stops the animation thread if running.
 *
 * @param s  Spinner handle (may be NULL).
 */
void kelp_spinner_free(kelp_spinner_t *s);

/**
 * Start the spinner animation in a background thread.
 *
 * @param s  Spinner handle.
 */
void kelp_spinner_start(kelp_spinner_t *s);

/**
 * Stop the spinner and display a final message.
 *
 * @param s              Spinner handle.
 * @param final_message  Message to display after stopping (may be NULL).
 */
void kelp_spinner_stop(kelp_spinner_t *s, const char *final_message);

/**
 * Update the message displayed beside the spinner while it is running.
 *
 * @param s    Spinner handle.
 * @param msg  New message string.
 */
void kelp_spinner_set_message(kelp_spinner_t *s, const char *msg);

#ifdef __cplusplus
}
#endif

#endif /* KELP_PROGRESS_H */
