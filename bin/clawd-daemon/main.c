/*
 * clawd-linux :: clawd-daemon
 * main.c - Daemon manager for systemd integration
 *
 * Usage: clawd-daemon <command> [options]
 * Commands:
 *   install   - Install systemd unit files
 *   uninstall - Remove systemd unit files
 *   start     - Start clawd gateway service
 *   stop      - Stop clawd gateway service
 *   restart   - Restart service
 *   status    - Show service status
 *   logs      - Show service logs (journalctl)
 *   enable    - Enable auto-start
 *   disable   - Disable auto-start
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/clawd.h>
#include <clawd/config.h>
#include <clawd/paths.h>

#include <errno.h>
#include <getopt.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#include <dbus/dbus.h>
#endif

/* ---- Constants ---------------------------------------------------------- */

#define CLAWD_DAEMON_VERSION "0.1.0"

#define SERVICE_NAME     "clawd-gateway.service"
#define SERVICE_DESC     "Clawd AI Gateway"
#define GATEWAY_BINARY   "/usr/bin/clawd-gateway"

/* ---- Global state ------------------------------------------------------- */

static clawd_config_t g_cfg;
static bool           g_user_mode   = false; /* --user vs --system */
static bool           g_verbose     = false;

/* ---- Unit file content -------------------------------------------------- */

static const char *SYSTEMD_UNIT_TEMPLATE =
    "[Unit]\n"
    "Description=" SERVICE_DESC "\n"
    "Documentation=man:clawd-gateway(1)\n"
    "After=network-online.target\n"
    "Wants=network-online.target\n"
    "\n"
    "[Service]\n"
    "Type=notify\n"
    "ExecStart=" GATEWAY_BINARY "\n"
    "ExecReload=/bin/kill -HUP $MAINPID\n"
    "Restart=on-failure\n"
    "RestartSec=5\n"
    "TimeoutStartSec=30\n"
    "TimeoutStopSec=30\n"
    "WatchdogSec=60\n"
    "\n"
    "# Security hardening\n"
    "ProtectSystem=strict\n"
    "ProtectHome=read-only\n"
    "PrivateTmp=yes\n"
    "NoNewPrivileges=yes\n"
    "CapabilityBoundingSet=\n"
    "AmbientCapabilities=\n"
    "SystemCallFilter=@system-service\n"
    "SystemCallErrorNumber=EPERM\n"
    "ProtectKernelModules=yes\n"
    "ProtectKernelTunables=yes\n"
    "ProtectControlGroups=yes\n"
    "RestrictNamespaces=yes\n"
    "RestrictRealtime=yes\n"
    "RestrictSUIDSGID=yes\n"
    "MemoryDenyWriteExecute=yes\n"
    "LockPersonality=yes\n"
    "\n"
    "# Resource limits\n"
    "LimitNOFILE=65536\n"
    "LimitNPROC=4096\n"
    "\n"
    "[Install]\n"
    "WantedBy=multi-user.target\n";

/* User-mode unit template (no User/Group, goes into ~/.config/systemd/user/). */
static const char *SYSTEMD_USER_UNIT_TEMPLATE =
    "[Unit]\n"
    "Description=" SERVICE_DESC "\n"
    "Documentation=man:clawd-gateway(1)\n"
    "After=network-online.target\n"
    "Wants=network-online.target\n"
    "\n"
    "[Service]\n"
    "Type=notify\n"
    "ExecStart=" GATEWAY_BINARY "\n"
    "ExecReload=/bin/kill -HUP $MAINPID\n"
    "Restart=on-failure\n"
    "RestartSec=5\n"
    "TimeoutStartSec=30\n"
    "TimeoutStopSec=30\n"
    "\n"
    "# Security hardening (user mode)\n"
    "NoNewPrivileges=yes\n"
    "ProtectSystem=strict\n"
    "PrivateTmp=yes\n"
    "\n"
    "[Install]\n"
    "WantedBy=default.target\n";

/* ---- Utility: run a command and return exit code ------------------------ */

static int run_command(const char *cmd)
{
    if (g_verbose)
        fprintf(stderr, "  + %s\n", cmd);

    int rc = system(cmd);
    if (rc == -1) {
        fprintf(stderr, "clawd-daemon: failed to execute: %s\n", cmd);
        return -1;
    }
    return WEXITSTATUS(rc);
}

/* ---- Utility: check if systemd is available ----------------------------- */

static bool systemd_available(void)
{
#ifdef __linux__
    struct stat st;
    /* Check for systemd runtime directory. */
    if (stat("/run/systemd/system", &st) == 0 && S_ISDIR(st.st_mode))
        return true;
    /* Fallback: check if systemctl exists. */
    if (access("/usr/bin/systemctl", X_OK) == 0)
        return true;
    if (access("/bin/systemctl", X_OK) == 0)
        return true;
#endif
    return false;
}

/* ---- Utility: get unit file path ---------------------------------------- */

static int get_unit_path(char *buf, size_t bufsz)
{
    if (g_user_mode) {
        const char *config_home = getenv("XDG_CONFIG_HOME");
        if (config_home) {
            snprintf(buf, bufsz, "%s/systemd/user/%s",
                     config_home, SERVICE_NAME);
        } else {
            const char *home = getenv("HOME");
            if (!home) {
                struct passwd *pw = getpwuid(getuid());
                home = pw ? pw->pw_dir : NULL;
            }
            if (!home) {
                fprintf(stderr, "clawd-daemon: cannot determine home directory\n");
                return -1;
            }
            snprintf(buf, bufsz, "%s/.config/systemd/user/%s",
                     home, SERVICE_NAME);
        }
    } else {
        snprintf(buf, bufsz, "/etc/systemd/system/%s", SERVICE_NAME);
    }
    return 0;
}

/* ---- Utility: ensure parent directory exists ---------------------------- */

static int ensure_parent_dir(const char *path)
{
    char *dir = strdup(path);
    if (!dir)
        return -1;

    /* Find the last slash and truncate. */
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        /* Recursively create directories. */
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", dir);
        int rc = run_command(cmd);
        free(dir);
        return rc;
    }
    free(dir);
    return 0;
}

/* ---- systemctl wrapper -------------------------------------------------- */

static int systemctl(const char *action, const char *unit)
{
    char cmd[512];
    if (g_user_mode) {
        snprintf(cmd, sizeof(cmd), "systemctl --user %s %s", action, unit);
    } else {
        snprintf(cmd, sizeof(cmd), "systemctl %s %s", action, unit);
    }
    return run_command(cmd);
}

static int systemctl_no_unit(const char *action)
{
    char cmd[256];
    if (g_user_mode) {
        snprintf(cmd, sizeof(cmd), "systemctl --user %s", action);
    } else {
        snprintf(cmd, sizeof(cmd), "systemctl %s", action);
    }
    return run_command(cmd);
}

/* ---- D-Bus communication with systemd (Linux) --------------------------- */

#ifdef __linux__

/**
 * Call a systemd Manager method via D-Bus.
 * This is the preferred method when libdbus is available.
 * Returns 0 on success, -1 on failure.
 */
static int systemd_dbus_call(const char *method, const char *unit_name)
{
    DBusError err;
    dbus_error_init(&err);

    /* Connect to the appropriate bus. */
    DBusBusType bus_type = g_user_mode ? DBUS_BUS_SESSION : DBUS_BUS_SYSTEM;
    DBusConnection *conn = dbus_bus_get(bus_type, &err);
    if (!conn || dbus_error_is_set(&err)) {
        if (g_verbose)
            fprintf(stderr, "  D-Bus connection failed: %s\n",
                    err.message ? err.message : "unknown");
        dbus_error_free(&err);
        return -1;
    }

    /* Create method call. */
    DBusMessage *msg = dbus_message_new_method_call(
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        method);

    if (!msg) {
        dbus_connection_unref(conn);
        return -1;
    }

    /* Append arguments depending on method. */
    if (strcmp(method, "StartUnit") == 0 ||
        strcmp(method, "StopUnit") == 0 ||
        strcmp(method, "RestartUnit") == 0) {
        const char *mode = "replace";
        dbus_message_append_args(msg,
                                 DBUS_TYPE_STRING, &unit_name,
                                 DBUS_TYPE_STRING, &mode,
                                 DBUS_TYPE_INVALID);
    } else if (strcmp(method, "EnableUnitFiles") == 0) {
        const char *units[] = { unit_name };
        int n_units = 1;
        dbus_bool_t runtime = FALSE;
        dbus_bool_t force = FALSE;

        DBusMessageIter iter;
        dbus_message_iter_init_append(msg, &iter);

        DBusMessageIter arr;
        dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &arr);
        for (int i = 0; i < n_units; i++)
            dbus_message_iter_append_basic(&arr, DBUS_TYPE_STRING, &units[i]);
        dbus_message_iter_close_container(&iter, &arr);
        dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &runtime);
        dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &force);
    } else if (strcmp(method, "DisableUnitFiles") == 0) {
        const char *units[] = { unit_name };
        int n_units = 1;
        dbus_bool_t runtime = FALSE;

        DBusMessageIter iter;
        dbus_message_iter_init_append(msg, &iter);

        DBusMessageIter arr;
        dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &arr);
        for (int i = 0; i < n_units; i++)
            dbus_message_iter_append_basic(&arr, DBUS_TYPE_STRING, &units[i]);
        dbus_message_iter_close_container(&iter, &arr);
        dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &runtime);
    } else if (strcmp(method, "GetUnitFileState") == 0) {
        dbus_message_append_args(msg,
                                 DBUS_TYPE_STRING, &unit_name,
                                 DBUS_TYPE_INVALID);
    }

    /* Send and wait for reply. */
    DBusMessage *reply = dbus_connection_send_with_reply_and_block(
        conn, msg, 30000, &err);

    dbus_message_unref(msg);

    if (!reply || dbus_error_is_set(&err)) {
        if (g_verbose)
            fprintf(stderr, "  D-Bus call %s failed: %s\n",
                    method, err.message ? err.message : "unknown");
        dbus_error_free(&err);
        dbus_connection_unref(conn);
        return -1;
    }

    /* For GetUnitFileState, extract and print the state. */
    if (strcmp(method, "GetUnitFileState") == 0) {
        const char *state = NULL;
        if (dbus_message_get_args(reply, &err,
                                  DBUS_TYPE_STRING, &state,
                                  DBUS_TYPE_INVALID)) {
            printf("Unit file state: %s\n", state);
        }
    }

    dbus_message_unref(reply);
    dbus_connection_unref(conn);
    return 0;
}

#endif /* __linux__ */

/* ---- Command: install --------------------------------------------------- */

static int cmd_install(void)
{
    if (!systemd_available()) {
        fprintf(stderr, "clawd-daemon: systemd is not available on this system\n");
#ifdef __APPLE__
        fprintf(stderr, "  On macOS, use 'clawd daemon install' for launchd support.\n");
#endif
        return 1;
    }

    char unit_path[512];
    if (get_unit_path(unit_path, sizeof(unit_path)) != 0)
        return 1;

    /* Check if already installed. */
    struct stat st;
    if (stat(unit_path, &st) == 0) {
        printf("Unit file already exists at %s\n", unit_path);
        printf("Use 'clawd-daemon uninstall' first to reinstall.\n");
        return 1;
    }

    /* Ensure parent directory exists. */
    if (ensure_parent_dir(unit_path) != 0) {
        fprintf(stderr, "clawd-daemon: cannot create directory for %s\n",
                unit_path);
        return 1;
    }

    /* Write the unit file. */
    const char *template = g_user_mode ? SYSTEMD_USER_UNIT_TEMPLATE
                                       : SYSTEMD_UNIT_TEMPLATE;

    FILE *f = fopen(unit_path, "w");
    if (!f) {
        fprintf(stderr, "clawd-daemon: cannot create %s: %s\n",
                unit_path, strerror(errno));
        if (!g_user_mode && geteuid() != 0) {
            fprintf(stderr, "  Hint: system-wide install requires root. "
                            "Use --user for user mode.\n");
        }
        return 1;
    }

    fprintf(f, "%s", template);
    fclose(f);

    printf("Installed unit file: %s\n", unit_path);

    /* Reload systemd daemon. */
    printf("Reloading systemd daemon...\n");
    systemctl_no_unit("daemon-reload");

    /* Enable linger for user services. */
    if (g_user_mode) {
        char linger_cmd[256];
        const char *user = getenv("USER");
        if (!user) {
            struct passwd *pw = getpwuid(getuid());
            user = pw ? pw->pw_name : NULL;
        }
        if (user) {
            snprintf(linger_cmd, sizeof(linger_cmd),
                     "loginctl enable-linger %s", user);
            printf("Enabling linger for user %s...\n", user);
            run_command(linger_cmd);
        }
    }

    printf("\nInstallation complete. Next steps:\n");
    if (g_user_mode) {
        printf("  clawd-daemon --user enable    Enable auto-start\n");
        printf("  clawd-daemon --user start     Start the service\n");
    } else {
        printf("  sudo clawd-daemon enable      Enable auto-start\n");
        printf("  sudo clawd-daemon start       Start the service\n");
    }

    return 0;
}

/* ---- Command: uninstall ------------------------------------------------- */

static int cmd_uninstall(void)
{
    if (!systemd_available()) {
        fprintf(stderr, "clawd-daemon: systemd is not available\n");
        return 1;
    }

    char unit_path[512];
    if (get_unit_path(unit_path, sizeof(unit_path)) != 0)
        return 1;

    /* Stop the service if running. */
    printf("Stopping service...\n");
    systemctl("stop", SERVICE_NAME);

    /* Disable the service. */
    printf("Disabling service...\n");
    systemctl("disable", SERVICE_NAME);

    /* Remove the unit file. */
    if (unlink(unit_path) == 0) {
        printf("Removed unit file: %s\n", unit_path);
    } else if (errno != ENOENT) {
        fprintf(stderr, "clawd-daemon: cannot remove %s: %s\n",
                unit_path, strerror(errno));
        return 1;
    } else {
        printf("Unit file not found: %s\n", unit_path);
    }

    /* Reload systemd daemon. */
    printf("Reloading systemd daemon...\n");
    systemctl_no_unit("daemon-reload");

    printf("Uninstallation complete.\n");
    return 0;
}

/* ---- Command: start ----------------------------------------------------- */

static int cmd_start(void)
{
    if (!systemd_available()) {
        fprintf(stderr, "clawd-daemon: systemd is not available\n");
        return 1;
    }

    printf("Starting %s...\n", SERVICE_NAME);

#ifdef __linux__
    /* Try D-Bus first. */
    if (systemd_dbus_call("StartUnit", SERVICE_NAME) == 0) {
        printf("Service started successfully.\n");
        return 0;
    }
    if (g_verbose)
        fprintf(stderr, "  D-Bus call failed, falling back to systemctl\n");
#endif

    int rc = systemctl("start", SERVICE_NAME);
    if (rc == 0)
        printf("Service started successfully.\n");
    else
        fprintf(stderr, "clawd-daemon: failed to start service (exit code %d)\n", rc);

    return rc;
}

/* ---- Command: stop ------------------------------------------------------ */

static int cmd_stop(void)
{
    if (!systemd_available()) {
        fprintf(stderr, "clawd-daemon: systemd is not available\n");
        return 1;
    }

    printf("Stopping %s...\n", SERVICE_NAME);

#ifdef __linux__
    if (systemd_dbus_call("StopUnit", SERVICE_NAME) == 0) {
        printf("Service stopped successfully.\n");
        return 0;
    }
    if (g_verbose)
        fprintf(stderr, "  D-Bus call failed, falling back to systemctl\n");
#endif

    int rc = systemctl("stop", SERVICE_NAME);
    if (rc == 0)
        printf("Service stopped successfully.\n");
    else
        fprintf(stderr, "clawd-daemon: failed to stop service (exit code %d)\n", rc);

    return rc;
}

/* ---- Command: restart --------------------------------------------------- */

static int cmd_restart(void)
{
    if (!systemd_available()) {
        fprintf(stderr, "clawd-daemon: systemd is not available\n");
        return 1;
    }

    printf("Restarting %s...\n", SERVICE_NAME);

#ifdef __linux__
    if (systemd_dbus_call("RestartUnit", SERVICE_NAME) == 0) {
        printf("Service restarted successfully.\n");
        return 0;
    }
    if (g_verbose)
        fprintf(stderr, "  D-Bus call failed, falling back to systemctl\n");
#endif

    int rc = systemctl("restart", SERVICE_NAME);
    if (rc == 0)
        printf("Service restarted successfully.\n");
    else
        fprintf(stderr, "clawd-daemon: failed to restart service (exit code %d)\n", rc);

    return rc;
}

/* ---- Command: status ---------------------------------------------------- */

static int cmd_status(void)
{
    if (!systemd_available()) {
        /* Fallback: check if gateway is running by looking at the PID file. */
        char *runtime_dir = clawd_paths_runtime_dir();
        if (runtime_dir) {
            char pidpath[512];
            snprintf(pidpath, sizeof(pidpath),
                     "%s/clawd-gateway.pid", runtime_dir);
            free(runtime_dir);

            FILE *f = fopen(pidpath, "r");
            if (f) {
                pid_t pid = 0;
                if (fscanf(f, "%d", &pid) == 1 && pid > 0) {
                    if (kill(pid, 0) == 0) {
                        printf("clawd-gateway is running (PID %d)\n", pid);
                        fclose(f);
                        return 0;
                    }
                }
                fclose(f);
            }
        }
        printf("clawd-gateway is not running\n");
        return 1;
    }

    /* Use systemctl status for detailed output. */
    return systemctl("status", SERVICE_NAME);
}

/* ---- Command: logs ------------------------------------------------------ */

static int cmd_logs(int argc, char **argv)
{
    if (!systemd_available()) {
        fprintf(stderr, "clawd-daemon: systemd / journalctl not available\n");
        return 1;
    }

    /* Build journalctl command. */
    clawd_str_t cmd = clawd_str_new();

    if (g_user_mode)
        clawd_str_append_cstr(&cmd, "journalctl --user");
    else
        clawd_str_append_cstr(&cmd, "journalctl");

    clawd_str_printf(&cmd, " -u %s", SERVICE_NAME);

    /* Pass through additional arguments (e.g., -f, -n 50, --since). */
    for (int i = 0; i < argc; i++) {
        clawd_str_printf(&cmd, " %s", argv[i]);
    }

    /* Default: show last 50 lines if no arguments given. */
    if (argc == 0)
        clawd_str_append_cstr(&cmd, " -n 50 --no-pager");

    int rc = run_command(cmd.data);
    clawd_str_free(&cmd);
    return rc;
}

/* ---- Command: enable ---------------------------------------------------- */

static int cmd_enable(void)
{
    if (!systemd_available()) {
        fprintf(stderr, "clawd-daemon: systemd is not available\n");
        return 1;
    }

    printf("Enabling %s...\n", SERVICE_NAME);

#ifdef __linux__
    if (systemd_dbus_call("EnableUnitFiles", SERVICE_NAME) == 0) {
        printf("Service enabled for auto-start.\n");
        return 0;
    }
    if (g_verbose)
        fprintf(stderr, "  D-Bus call failed, falling back to systemctl\n");
#endif

    int rc = systemctl("enable", SERVICE_NAME);
    if (rc == 0)
        printf("Service enabled for auto-start.\n");
    else
        fprintf(stderr, "clawd-daemon: failed to enable service (exit code %d)\n", rc);

    return rc;
}

/* ---- Command: disable --------------------------------------------------- */

static int cmd_disable(void)
{
    if (!systemd_available()) {
        fprintf(stderr, "clawd-daemon: systemd is not available\n");
        return 1;
    }

    printf("Disabling %s...\n", SERVICE_NAME);

#ifdef __linux__
    if (systemd_dbus_call("DisableUnitFiles", SERVICE_NAME) == 0) {
        printf("Service auto-start disabled.\n");
        return 0;
    }
    if (g_verbose)
        fprintf(stderr, "  D-Bus call failed, falling back to systemctl\n");
#endif

    int rc = systemctl("disable", SERVICE_NAME);
    if (rc == 0)
        printf("Service auto-start disabled.\n");
    else
        fprintf(stderr, "clawd-daemon: failed to disable service (exit code %d)\n", rc);

    return rc;
}

/* ---- Usage -------------------------------------------------------------- */

static void usage(void)
{
    printf(
        "Usage: clawd-daemon [options] <command> [args...]\n"
        "\n"
        "Commands:\n"
        "  install     Install systemd unit files\n"
        "  uninstall   Remove systemd unit files\n"
        "  start       Start clawd gateway service\n"
        "  stop        Stop clawd gateway service\n"
        "  restart     Restart service\n"
        "  status      Show service status\n"
        "  logs        Show service logs (journalctl)\n"
        "  enable      Enable auto-start on boot\n"
        "  disable     Disable auto-start on boot\n"
        "\n"
        "Options:\n"
        "  -c, --config <path>   Configuration file path\n"
        "  -u, --user            User mode (systemd --user)\n"
        "      --system          System mode (default, requires root)\n"
        "  -v, --verbose         Verbose output\n"
        "  -h, --help            Show this help\n"
        "  -V, --version         Show version\n"
        "\n"
        "The 'logs' command passes extra arguments to journalctl:\n"
        "  clawd-daemon logs -f              Follow log output\n"
        "  clawd-daemon logs -n 100          Show last 100 lines\n"
        "  clawd-daemon logs --since today   Show today's logs\n"
        "\n"
        "Examples:\n"
        "  sudo clawd-daemon install         Install system-wide service\n"
        "  clawd-daemon --user install       Install user service\n"
        "  sudo clawd-daemon start           Start the service\n"
        "  clawd-daemon --user status        Check user service status\n"
        "  clawd-daemon logs -f              Follow service logs\n"
        "\n"
    );
}

/* ---- Main --------------------------------------------------------------- */

int main(int argc, char **argv)
{
    const char *config_path = NULL;

    enum { OPT_SYSTEM = 256 };

    static struct option long_options[] = {
        {"config",  required_argument, NULL, 'c'},
        {"user",    no_argument,       NULL, 'u'},
        {"system",  no_argument,       NULL, OPT_SYSTEM},
        {"verbose", no_argument,       NULL, 'v'},
        {"help",    no_argument,       NULL, 'h'},
        {"version", no_argument,       NULL, 'V'},
        {NULL,      0,                 NULL,  0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "+c:uvhV", long_options, NULL)) != -1) {
        switch (opt) {
        case 'c':
            config_path = optarg;
            break;
        case 'u':
            g_user_mode = true;
            break;
        case OPT_SYSTEM:
            g_user_mode = false;
            break;
        case 'v':
            g_verbose = true;
            break;
        case 'h':
            usage();
            return 0;
        case 'V':
            printf("clawd-daemon %s\n", CLAWD_DAEMON_VERSION);
            return 0;
        default:
            fprintf(stderr, "Try 'clawd-daemon --help' for more information.\n");
            return 1;
        }
    }

    /* Auto-detect user mode if not root and not explicitly set. */
    if (!g_user_mode && geteuid() != 0) {
        /* Check if --system was explicitly passed. */
        bool system_explicit = false;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--system") == 0) {
                system_explicit = true;
                break;
            }
        }
        if (!system_explicit) {
            g_user_mode = true;
            if (g_verbose)
                fprintf(stderr, "  Auto-selecting --user mode (not running as root)\n");
        }
    }

    /* Load configuration. */
    if (config_path) {
        if (clawd_config_load(config_path, &g_cfg) != 0) {
            fprintf(stderr, "clawd-daemon: warning: failed to load config: %s\n",
                    config_path);
        }
    } else {
        clawd_config_load_default(&g_cfg);
    }
    clawd_config_merge_env(&g_cfg);

    /* Initialize logging. */
    clawd_log_init("clawd-daemon", g_verbose ? CLAWD_LOG_DEBUG : CLAWD_LOG_WARN);

    /* Determine command. */
    if (optind >= argc) {
        usage();
        clawd_config_free(&g_cfg);
        return 1;
    }

    const char *command = argv[optind];
    int sub_argc = argc - optind - 1;
    char **sub_argv = argv + optind + 1;

    int ret = 0;

    if (strcmp(command, "install") == 0) {
        ret = cmd_install();
    } else if (strcmp(command, "uninstall") == 0) {
        ret = cmd_uninstall();
    } else if (strcmp(command, "start") == 0) {
        ret = cmd_start();
    } else if (strcmp(command, "stop") == 0) {
        ret = cmd_stop();
    } else if (strcmp(command, "restart") == 0) {
        ret = cmd_restart();
    } else if (strcmp(command, "status") == 0) {
        ret = cmd_status();
    } else if (strcmp(command, "logs") == 0) {
        ret = cmd_logs(sub_argc, sub_argv);
    } else if (strcmp(command, "enable") == 0) {
        ret = cmd_enable();
    } else if (strcmp(command, "disable") == 0) {
        ret = cmd_disable();
    } else {
        fprintf(stderr, "clawd-daemon: unknown command '%s'\n", command);
        fprintf(stderr, "Try 'clawd-daemon --help' for more information.\n");
        ret = 1;
    }

    clawd_config_free(&g_cfg);
    return ret;
}
