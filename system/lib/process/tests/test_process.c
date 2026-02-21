/*
 * kelp-linux :: libkelp-process
 * test_process.c - Unit tests for process, PTY, signal, and supervisor APIs
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/process.h>
#include <kelp/pty.h>
#include <kelp/signals.h>
#include <kelp/supervisor.h>
#include <kelp/log.h>

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/wait.h>

/* ---- helpers ------------------------------------------------------------ */

#define TEST_BEGIN(name)                                                       \
    do {                                                                       \
        printf("  %-50s ", name);                                              \
        fflush(stdout);                                                        \
    } while (0)

#define TEST_PASS()                                                            \
    do {                                                                       \
        printf("PASS\n");                                                      \
    } while (0)

static int tests_run    = 0;
static int tests_passed = 0;

/* ---- test: exec simple command (echo) ----------------------------------- */

static void test_exec_echo(void)
{
    TEST_BEGIN("exec echo and capture stdout");
    tests_run++;

    char *argv[] = {"echo", "hello world", NULL};
    kelp_proc_opts_t opts = {0};
    opts.cmd            = "echo";
    opts.argv           = argv;
    opts.capture_stdout = true;
    opts.set_pgid       = true;

    kelp_proc_result_t result = {0};
    int rc = kelp_proc_exec(&opts, &result);

    assert(rc == 0);
    assert(result.exit_code == 0);
    assert(!result.timed_out);
    assert(result.stdout_data != NULL);
    assert(result.stdout_len > 0);
    assert(strncmp(result.stdout_data, "hello world", 11) == 0);

    kelp_proc_result_free(&result);

    TEST_PASS();
    tests_passed++;
}

/* ---- test: exec with stderr capture ------------------------------------- */

static void test_exec_stderr(void)
{
    TEST_BEGIN("exec command with stderr capture");
    tests_run++;

    /* Use sh -c to write to stderr */
    char *argv[] = {"sh", "-c", "echo error_msg >&2", NULL};
    kelp_proc_opts_t opts = {0};
    opts.cmd            = "sh";
    opts.argv           = argv;
    opts.capture_stderr = true;
    opts.set_pgid       = true;

    kelp_proc_result_t result = {0};
    int rc = kelp_proc_exec(&opts, &result);

    assert(rc == 0);
    assert(result.exit_code == 0);
    assert(result.stderr_data != NULL);
    assert(result.stderr_len > 0);
    assert(strstr(result.stderr_data, "error_msg") != NULL);

    kelp_proc_result_free(&result);

    TEST_PASS();
    tests_passed++;
}

/* ---- test: exec with merged stderr -------------------------------------- */

static void test_exec_merge_stderr(void)
{
    TEST_BEGIN("exec with stderr merged into stdout");
    tests_run++;

    char *argv[] = {"sh", "-c",
                    "echo stdout_line; echo stderr_line >&2", NULL};
    kelp_proc_opts_t opts = {0};
    opts.cmd            = "sh";
    opts.argv           = argv;
    opts.capture_stdout = true;
    opts.merge_stderr   = true;
    opts.set_pgid       = true;

    kelp_proc_result_t result = {0};
    int rc = kelp_proc_exec(&opts, &result);

    assert(rc == 0);
    assert(result.exit_code == 0);
    assert(result.stdout_data != NULL);
    /* Both lines should appear in stdout */
    assert(strstr(result.stdout_data, "stdout_line") != NULL);
    assert(strstr(result.stdout_data, "stderr_line") != NULL);
    /* stderr_data should be empty since we merged */
    assert(result.stderr_data == NULL || result.stderr_len == 0);

    kelp_proc_result_free(&result);

    TEST_PASS();
    tests_passed++;
}

/* ---- test: exec with stdin data ----------------------------------------- */

static void test_exec_stdin(void)
{
    TEST_BEGIN("exec with stdin data piped in");
    tests_run++;

    char *argv[] = {"cat", NULL};
    const char *input = "piped input\n";
    kelp_proc_opts_t opts = {0};
    opts.cmd            = "cat";
    opts.argv           = argv;
    opts.stdin_data     = input;
    opts.stdin_len      = strlen(input);
    opts.capture_stdout = true;
    opts.set_pgid       = true;

    kelp_proc_result_t result = {0};
    int rc = kelp_proc_exec(&opts, &result);

    assert(rc == 0);
    assert(result.exit_code == 0);
    assert(result.stdout_data != NULL);
    assert(strncmp(result.stdout_data, "piped input", 11) == 0);

    kelp_proc_result_free(&result);

    TEST_PASS();
    tests_passed++;
}

/* ---- test: exec nonexistent command ------------------------------------- */

static void test_exec_not_found(void)
{
    TEST_BEGIN("exec nonexistent command returns 127");
    tests_run++;

    char *argv[] = {"__kelp_no_such_command__", NULL};
    kelp_proc_opts_t opts = {0};
    opts.cmd      = "__kelp_no_such_command__";
    opts.argv     = argv;
    opts.set_pgid = true;

    kelp_proc_result_t result = {0};
    int rc = kelp_proc_exec(&opts, &result);

    assert(rc == 0);
    assert(result.exit_code == 127);

    kelp_proc_result_free(&result);

    TEST_PASS();
    tests_passed++;
}

/* ---- test: exec with timeout -------------------------------------------- */

static void test_exec_timeout(void)
{
    TEST_BEGIN("exec with timeout (sleep)");
    tests_run++;

    char *argv[] = {"sleep", "60", NULL};
    kelp_proc_opts_t opts = {0};
    opts.cmd        = "sleep";
    opts.argv       = argv;
    opts.timeout_ms = 500;   /* 500ms timeout; sleep would take 60s */
    opts.set_pgid   = true;

    kelp_proc_result_t result = {0};
    int rc = kelp_proc_exec(&opts, &result);

    assert(rc == 0);
    assert(result.timed_out);

    kelp_proc_result_free(&result);

    TEST_PASS();
    tests_passed++;
}

/* ---- test: exec exit code ----------------------------------------------- */

static void test_exec_exit_code(void)
{
    TEST_BEGIN("exec captures non-zero exit code");
    tests_run++;

    char *argv[] = {"sh", "-c", "exit 42", NULL};
    kelp_proc_opts_t opts = {0};
    opts.cmd      = "sh";
    opts.argv     = argv;
    opts.set_pgid = true;

    kelp_proc_result_t result = {0};
    int rc = kelp_proc_exec(&opts, &result);

    assert(rc == 0);
    assert(result.exit_code == 42);
    assert(!result.timed_out);

    kelp_proc_result_free(&result);

    TEST_PASS();
    tests_passed++;
}

/* ---- test: spawn and wait ----------------------------------------------- */

static void test_spawn_and_wait(void)
{
    TEST_BEGIN("spawn then wait for child");
    tests_run++;

    char *argv[] = {"sh", "-c", "exit 7", NULL};
    kelp_proc_opts_t opts = {0};
    opts.cmd      = "sh";
    opts.argv     = argv;
    opts.set_pgid = true;

    pid_t pid = kelp_proc_spawn(&opts);
    assert(pid > 0);

    kelp_proc_result_t result = {0};
    int rc = kelp_proc_wait(pid, 5000, &result);
    assert(rc == 0);
    assert(result.exit_code == 7);

    kelp_proc_result_free(&result);

    TEST_PASS();
    tests_passed++;
}

/* ---- test: kill_tree ----------------------------------------------------- */

static void test_kill_tree(void)
{
    TEST_BEGIN("kill_tree terminates process group");
    tests_run++;

    /* Spawn a process that itself spawns children */
    char *argv[] = {"sh", "-c", "sleep 300 & sleep 300 & wait", NULL};
    kelp_proc_opts_t opts = {0};
    opts.cmd      = "sh";
    opts.argv     = argv;
    opts.set_pgid = true;

    pid_t pid = kelp_proc_spawn(&opts);
    assert(pid > 0);

    /* Give children a moment to spawn */
    usleep(100000);  /* 100ms */

    /* Kill the entire process group */
    int rc = kelp_proc_kill_tree(pid, SIGKILL);
    assert(rc == 0);

    /* Reap the parent */
    int status;
    waitpid(pid, &status, 0);

    /* Verify the parent is gone */
    assert(!kelp_proc_is_running(pid));

    TEST_PASS();
    tests_passed++;
}

/* ---- test: is_running --------------------------------------------------- */

static void test_is_running(void)
{
    TEST_BEGIN("is_running checks process existence");
    tests_run++;

    /* Our own pid should be running */
    assert(kelp_proc_is_running(getpid()));

    /* A very high PID should not exist */
    assert(!kelp_proc_is_running(99999999));

    TEST_PASS();
    tests_passed++;
}

/* ---- test: PTY open/close ----------------------------------------------- */

static void test_pty_open_close(void)
{
    TEST_BEGIN("pty open and close");
    tests_run++;

    kelp_pty_t pty = {0};
    pty.master_fd = -1;
    pty.slave_fd  = -1;

    int rc = kelp_pty_open(&pty);
    assert(rc == 0);
    assert(pty.master_fd >= 0);
    assert(pty.slave_fd >= 0);
    assert(strlen(pty.slave_name) > 0);

    kelp_pty_close(&pty);
    assert(pty.master_fd == -1);
    assert(pty.slave_fd == -1);

    TEST_PASS();
    tests_passed++;
}

/* ---- test: PTY fork and read -------------------------------------------- */

static void test_pty_fork_echo(void)
{
    TEST_BEGIN("pty fork and read from child");
    tests_run++;

    kelp_pty_t pty = {0};
    pty.master_fd = -1;
    pty.slave_fd  = -1;

    char *argv[] = {"echo", "pty_output", NULL};
    pid_t pid = kelp_pty_fork(&pty, "echo", argv);
    assert(pid > 0);
    assert(pty.master_fd >= 0);

    /* Read output from PTY */
    char buf[256] = {0};
    usleep(100000);  /* give child time to run */
    ssize_t n = kelp_pty_read(&pty, buf, sizeof(buf) - 1);

    /* The child might have exited before we read, or we get some output.
     * PTY output may include extra \r characters. */
    if (n > 0) {
        buf[n] = '\0';
        assert(strstr(buf, "pty_output") != NULL);
    }

    /* Reap child */
    int status;
    waitpid(pid, &status, 0);

    kelp_pty_close(&pty);

    TEST_PASS();
    tests_passed++;
}

/* ---- test: PTY resize --------------------------------------------------- */

static void test_pty_resize(void)
{
    TEST_BEGIN("pty resize sends TIOCSWINSZ");
    tests_run++;

    kelp_pty_t pty = {0};
    pty.master_fd = -1;
    pty.slave_fd  = -1;

    int rc = kelp_pty_open(&pty);
    assert(rc == 0);

    /* Resize should succeed on an open PTY */
    rc = kelp_pty_resize(&pty, 40, 120);
    assert(rc == 0);

    kelp_pty_close(&pty);

    TEST_PASS();
    tests_passed++;
}

/* ---- test: signal context create/destroy -------------------------------- */

static void test_signal_ctx(void)
{
    TEST_BEGIN("signal context create and destroy");
    tests_run++;

    kelp_signal_ctx_t *ctx = kelp_signal_ctx_new();
    assert(ctx != NULL);

    int fd = kelp_signal_fd(ctx);
    assert(fd >= 0);

    kelp_signal_ctx_free(ctx);

    TEST_PASS();
    tests_passed++;
}

/* ---- test: signal watch and dispatch ------------------------------------ */

static volatile int signal_received = 0;

static void test_signal_handler(int signo, void *userdata)
{
    (void)signo;
    int *counter = (int *)userdata;
    (*counter)++;
    signal_received = 1;
}

static void test_signal_watch(void)
{
    TEST_BEGIN("signal watch and dispatch (SIGUSR1)");
    tests_run++;

    int counter = 0;
    signal_received = 0;

    kelp_signal_ctx_t *ctx = kelp_signal_ctx_new();
    assert(ctx != NULL);

    int rc = kelp_signal_watch(ctx, SIGUSR1, test_signal_handler, &counter);
    assert(rc == 0);

    /* Send ourselves SIGUSR1 */
    kill(getpid(), SIGUSR1);

    /* Give the signal a moment to be delivered */
    usleep(50000);  /* 50ms */

    /* Dispatch should invoke our handler */
    int dispatched = kelp_signal_dispatch(ctx);
    assert(dispatched >= 0);

    /*
     * On macOS the self-pipe should have delivered the signal.
     * On Linux the signalfd should have it.
     * Either way, counter should be >= 1.
     */
    assert(counter >= 1);

    kelp_signal_ctx_free(ctx);

    TEST_PASS();
    tests_passed++;
}

/* ---- test: supervisor create/destroy ------------------------------------ */

static void test_supervisor_lifecycle(void)
{
    TEST_BEGIN("supervisor create, add, start, stop, free");
    tests_run++;

    kelp_supervisor_t *sv = kelp_supervisor_new();
    assert(sv != NULL);

    /* Add a simple long-running process */
    char *argv[] = {"sleep", "300", NULL};
    kelp_supervised_t proc = {
        .name             = "test-sleep",
        .cmd              = "sleep",
        .argv             = argv,
        .restart_delay_ms = 100,
        .max_restarts     = 3,
        .auto_restart     = true
    };

    int rc = kelp_supervisor_add(sv, &proc);
    assert(rc == 0);

    /* Duplicate name should fail */
    rc = kelp_supervisor_add(sv, &proc);
    assert(rc == -1);

    /* Start should launch the process */
    rc = kelp_supervisor_start(sv);
    assert(rc == 0);

    /* Give the child a moment to start */
    usleep(100000);

    /* Stop and free should terminate the child */
    kelp_supervisor_stop(sv);

    /* Restart after stop should work */
    rc = kelp_supervisor_restart(sv, "test-sleep");
    assert(rc == 0);

    usleep(100000);

    kelp_supervisor_free(sv);

    TEST_PASS();
    tests_passed++;
}

/* ---- test: supervisor restart by name ----------------------------------- */

static void test_supervisor_restart(void)
{
    TEST_BEGIN("supervisor restart by name");
    tests_run++;

    kelp_supervisor_t *sv = kelp_supervisor_new();
    assert(sv != NULL);

    char *argv[] = {"sleep", "300", NULL};
    kelp_supervised_t proc = {
        .name             = "restartable",
        .cmd              = "sleep",
        .argv             = argv,
        .restart_delay_ms = 100,
        .max_restarts     = 0,    /* unlimited */
        .auto_restart     = false
    };

    int rc = kelp_supervisor_add(sv, &proc);
    assert(rc == 0);

    rc = kelp_supervisor_start(sv);
    assert(rc == 0);
    usleep(100000);

    /* Restart should succeed */
    rc = kelp_supervisor_restart(sv, "restartable");
    assert(rc == 0);
    usleep(100000);

    /* Restart non-existent name should fail */
    rc = kelp_supervisor_restart(sv, "nonexistent");
    assert(rc == -1);

    kelp_supervisor_free(sv);

    TEST_PASS();
    tests_passed++;
}

/* ---- test: proc_result_free on zeroed struct ---------------------------- */

static void test_result_free_null(void)
{
    TEST_BEGIN("proc_result_free on NULL and zeroed struct");
    tests_run++;

    /* Should not crash */
    kelp_proc_result_free(NULL);

    kelp_proc_result_t result = {0};
    kelp_proc_result_free(&result);

    TEST_PASS();
    tests_passed++;
}

/* ---- main --------------------------------------------------------------- */

int main(void)
{
    kelp_log_init("test_process", KELP_LOG_WARN);

    printf("\n=== libkelp-process tests ===\n\n");

    /* Process execution tests */
    test_exec_echo();
    test_exec_stderr();
    test_exec_merge_stderr();
    test_exec_stdin();
    test_exec_not_found();
    test_exec_timeout();
    test_exec_exit_code();
    test_spawn_and_wait();
    test_kill_tree();
    test_is_running();
    test_result_free_null();

    /* PTY tests */
    test_pty_open_close();
    test_pty_fork_echo();
    test_pty_resize();

    /* Signal tests */
    test_signal_ctx();
    test_signal_watch();

    /* Supervisor tests */
    test_supervisor_lifecycle();
    test_supervisor_restart();

    printf("\n  Results: %d/%d tests passed\n\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
