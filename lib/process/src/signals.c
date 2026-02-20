/*
 * clawd-linux :: libclawd-process
 * signals.c - Signal bridge via signalfd (Linux) or self-pipe (macOS/BSD)
 *
 * Provides a file-descriptor-based interface so that signals can be
 * integrated into epoll / kqueue / poll event loops.
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/signals.h>
#include <clawd/log.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/signalfd.h>
#endif

/* ---- constants ---------------------------------------------------------- */

/* Maximum signal number we support.  NSIG is typically 64 on Linux. */
#ifndef CLAWD_MAX_SIGNALS
#define CLAWD_MAX_SIGNALS 64
#endif

/* ---- per-signal registration -------------------------------------------- */

typedef struct {
    clawd_signal_handler_t handler;
    void                  *userdata;
    bool                   active;
} signal_slot_t;

/* ---- context struct ----------------------------------------------------- */

struct clawd_signal_ctx {
    signal_slot_t  slots[CLAWD_MAX_SIGNALS];

#ifdef __linux__
    int            sfd;          /* signalfd descriptor         */
    sigset_t       mask;         /* signals blocked via mask    */
#else
    int            pipe_rd;      /* self-pipe read end          */
    int            pipe_wr;      /* self-pipe write end         */
#endif
};

/* ---- macOS / BSD self-pipe implementation ------------------------------- */

#ifndef __linux__

/*
 * Global pointer to the active context -- needed because signal handlers
 * do not receive a user-data argument.  Only one signal context may be
 * active at a time (which matches the semantics of signalfd on Linux).
 */
static clawd_signal_ctx_t *g_active_ctx = NULL;

/* Saved original signal actions so we can restore them on cleanup. */
static struct sigaction g_orig_actions[CLAWD_MAX_SIGNALS];
static bool            g_orig_saved[CLAWD_MAX_SIGNALS];

/**
 * Async-signal-safe handler that writes the signal number to the self-pipe.
 */
static void selfpipe_handler(int signo)
{
    clawd_signal_ctx_t *ctx = g_active_ctx;
    if (!ctx || ctx->pipe_wr < 0)
        return;

    unsigned char byte = (unsigned char)(signo & 0xFF);
    /* write() to a pipe is async-signal-safe per POSIX */
    (void)write(ctx->pipe_wr, &byte, 1);
}

#endif /* !__linux__ */

/* ---- helpers ------------------------------------------------------------ */

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int set_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

/* ---- public API --------------------------------------------------------- */

clawd_signal_ctx_t *clawd_signal_ctx_new(void)
{
    clawd_signal_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

#ifdef __linux__
    sigemptyset(&ctx->mask);
    ctx->sfd = -1;
#else
    ctx->pipe_rd = -1;
    ctx->pipe_wr = -1;

    int fds[2];
    if (pipe(fds) < 0) {
        free(ctx);
        return NULL;
    }

    ctx->pipe_rd = fds[0];
    ctx->pipe_wr = fds[1];

    set_nonblock(ctx->pipe_rd);
    set_nonblock(ctx->pipe_wr);
    set_cloexec(ctx->pipe_rd);
    set_cloexec(ctx->pipe_wr);

    g_active_ctx = ctx;
#endif

    CLAWD_TRACE("signal context created");
    return ctx;
}

void clawd_signal_ctx_free(clawd_signal_ctx_t *ctx)
{
    if (!ctx)
        return;

#ifdef __linux__
    /* Restore signal mask (unblock watched signals) */
    if (ctx->sfd >= 0) {
        sigprocmask(SIG_UNBLOCK, &ctx->mask, NULL);
        close(ctx->sfd);
    }
#else
    /* Restore original signal dispositions */
    for (int i = 0; i < CLAWD_MAX_SIGNALS; i++) {
        if (ctx->slots[i].active && g_orig_saved[i]) {
            sigaction(i, &g_orig_actions[i], NULL);
            g_orig_saved[i] = false;
        }
    }

    if (ctx->pipe_rd >= 0) close(ctx->pipe_rd);
    if (ctx->pipe_wr >= 0) close(ctx->pipe_wr);

    if (g_active_ctx == ctx)
        g_active_ctx = NULL;
#endif

    CLAWD_TRACE("signal context freed");
    free(ctx);
}

int clawd_signal_watch(clawd_signal_ctx_t *ctx, int signo,
                       clawd_signal_handler_t handler, void *userdata)
{
    if (!ctx || !handler)
        return -1;
    if (signo < 1 || signo >= CLAWD_MAX_SIGNALS)
        return -1;

    ctx->slots[signo].handler  = handler;
    ctx->slots[signo].userdata = userdata;
    ctx->slots[signo].active   = true;

#ifdef __linux__
    /* Add signal to our blocked-mask */
    sigaddset(&ctx->mask, signo);

    /* Block the signal so it goes to signalfd instead of the default handler */
    if (sigprocmask(SIG_BLOCK, &ctx->mask, NULL) < 0) {
        CLAWD_ERROR("sigprocmask failed: %s", strerror(errno));
        return -1;
    }

    /* (Re-)create the signalfd with the updated mask */
    int new_sfd = signalfd(ctx->sfd, &ctx->mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (new_sfd < 0) {
        CLAWD_ERROR("signalfd failed: %s", strerror(errno));
        return -1;
    }
    ctx->sfd = new_sfd;

#else
    /* macOS: install a signal handler that writes to the self-pipe */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = selfpipe_handler;
    sa.sa_flags   = SA_RESTART;
    sigemptyset(&sa.sa_mask);

    /* Save original handler */
    if (!g_orig_saved[signo]) {
        sigaction(signo, NULL, &g_orig_actions[signo]);
        g_orig_saved[signo] = true;
    }

    if (sigaction(signo, &sa, NULL) < 0) {
        CLAWD_ERROR("sigaction(%d) failed: %s", signo, strerror(errno));
        return -1;
    }
#endif

    CLAWD_TRACE("watching signal %d", signo);
    return 0;
}

int clawd_signal_fd(clawd_signal_ctx_t *ctx)
{
    if (!ctx)
        return -1;

#ifdef __linux__
    return ctx->sfd;
#else
    return ctx->pipe_rd;
#endif
}

int clawd_signal_dispatch(clawd_signal_ctx_t *ctx)
{
    if (!ctx)
        return -1;

    int dispatched = 0;

#ifdef __linux__
    if (ctx->sfd < 0)
        return -1;

    for (;;) {
        struct signalfd_siginfo si;
        ssize_t n = read(ctx->sfd, &si, sizeof(si));
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if (errno == EINTR)
                continue;
            return -1;
        }
        if ((size_t)n < sizeof(si))
            break;

        int signo = (int)si.ssi_signo;
        if (signo >= 0 && signo < CLAWD_MAX_SIGNALS &&
            ctx->slots[signo].active) {
            ctx->slots[signo].handler(signo, ctx->slots[signo].userdata);
            dispatched++;
        }
    }

#else
    if (ctx->pipe_rd < 0)
        return -1;

    for (;;) {
        unsigned char byte;
        ssize_t n = read(ctx->pipe_rd, &byte, 1);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            break;

        int signo = (int)byte;
        if (signo >= 0 && signo < CLAWD_MAX_SIGNALS &&
            ctx->slots[signo].active) {
            ctx->slots[signo].handler(signo, ctx->slots[signo].userdata);
            dispatched++;
        }
    }
#endif

    return dispatched;
}
