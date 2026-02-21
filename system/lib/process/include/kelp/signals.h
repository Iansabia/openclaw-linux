/*
 * kelp-linux :: libkelp-process
 * signals.h - Signal bridge (signalfd on Linux, self-pipe on macOS)
 *
 * Provides a file-descriptor-based signal delivery mechanism suitable
 * for integration with epoll / kqueue event loops.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_SIGNALS_H
#define KELP_SIGNALS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Signal handler callback.
 *
 * @param signo     The signal number that was delivered.
 * @param userdata  Opaque pointer supplied at registration time.
 */
typedef void (*kelp_signal_handler_t)(int signo, void *userdata);

/**
 * Opaque signal context.
 */
typedef struct kelp_signal_ctx kelp_signal_ctx_t;

/**
 * Create a new signal context.
 *
 * Returns NULL on allocation failure.
 */
kelp_signal_ctx_t *kelp_signal_ctx_new(void);

/**
 * Destroy a signal context and restore the original signal dispositions
 * for all watched signals.
 */
void kelp_signal_ctx_free(kelp_signal_ctx_t *ctx);

/**
 * Register a handler for `signo`.
 *
 * On Linux the signal is added to the signalfd mask.
 * On macOS/BSD a self-pipe signal handler is installed.
 *
 * Returns 0 on success, -1 on failure.
 */
int kelp_signal_watch(kelp_signal_ctx_t *ctx, int signo,
                       kelp_signal_handler_t handler, void *userdata);

/**
 * Return a file descriptor that becomes readable when a watched signal
 * has been delivered.  Suitable for epoll_ctl / kevent / poll.
 *
 * Returns -1 if the context is invalid.
 */
int kelp_signal_fd(kelp_signal_ctx_t *ctx);

/**
 * Read pending signal(s) from the fd and invoke the registered handlers.
 *
 * Returns the number of signals dispatched, or -1 on error.
 */
int kelp_signal_dispatch(kelp_signal_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* KELP_SIGNALS_H */
