/*
 * kelp-linux :: libkelp-terminal
 * prompt.c - Reusable terminal prompt helpers
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/prompt.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

/* Maximum line length for fgets-based reads */
#define PROMPT_LINE_MAX 4096

/* ---- Helpers ------------------------------------------------------------ */

/*
 * Read a line from stdin via fgets, trim the trailing newline, and return
 * a heap-allocated copy.  Returns NULL on EOF or allocation failure.
 */
static char *read_line(void)
{
    char buf[PROMPT_LINE_MAX];
    if (!fgets(buf, sizeof(buf), stdin)) {
        return NULL;
    }

    /* Trim trailing newline / carriage return */
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[--len] = '\0';
    }

    char *result = (char *)malloc(len + 1);
    if (!result) return NULL;
    memcpy(result, buf, len + 1);
    return result;
}

/* ---- Public API --------------------------------------------------------- */

bool kelp_prompt_confirm(const char *message, bool default_yes)
{
    if (!message) message = "Confirm?";

    fprintf(stdout, "%s %s ", message, default_yes ? "[Y/n]" : "[y/N]");
    fflush(stdout);

    char *line = read_line();
    if (!line) {
        /* EOF -- return the default */
        return default_yes;
    }

    bool result;
    if (line[0] == '\0') {
        /* Empty input -- use default */
        result = default_yes;
    } else if (tolower((unsigned char)line[0]) == 'y') {
        result = true;
    } else if (tolower((unsigned char)line[0]) == 'n') {
        result = false;
    } else {
        /* Unrecognised input -- use default */
        result = default_yes;
    }

    free(line);
    return result;
}

int kelp_prompt_select(const char *message, const char **options, int count)
{
    if (!options || count <= 0) return -1;

    if (message && *message) {
        fprintf(stdout, "%s\n", message);
    }

    for (int i = 0; i < count; i++) {
        fprintf(stdout, "  %d) %s\n", i + 1, options[i] ? options[i] : "");
    }

    fprintf(stdout, "Choice [1-%d]: ", count);
    fflush(stdout);

    char *line = read_line();
    if (!line) return -1;

    char *end = NULL;
    long choice = strtol(line, &end, 10);
    free(line);

    if (end == line || choice < 1 || choice > count) {
        return -1;
    }

    return (int)(choice - 1);
}

char *kelp_prompt_input(const char *message, const char *default_value)
{
    if (!message) message = "Input";

    if (default_value && *default_value) {
        fprintf(stdout, "%s [%s]: ", message, default_value);
    } else {
        fprintf(stdout, "%s: ", message);
    }
    fflush(stdout);

    char *line = read_line();
    if (!line) return NULL;

    /* If the line is empty and we have a default, return a copy of it */
    if (line[0] == '\0' && default_value && *default_value) {
        free(line);
        size_t dlen = strlen(default_value);
        char *dup = (char *)malloc(dlen + 1);
        if (!dup) return NULL;
        memcpy(dup, default_value, dlen + 1);
        return dup;
    }

    return line;
}

char *kelp_prompt_password(const char *message)
{
    if (!message) message = "Password";

    fprintf(stdout, "%s: ", message);
    fflush(stdout);

    /* Disable echo via termios */
    struct termios old_attr, new_attr;
    int tty_fd = fileno(stdin);
    bool termios_ok = (tcgetattr(tty_fd, &old_attr) == 0);

    if (termios_ok) {
        new_attr = old_attr;
        new_attr.c_lflag &= ~((tcflag_t)ECHO);
        tcsetattr(tty_fd, TCSANOW, &new_attr);
    }

    char *line = read_line();

    /* Restore terminal settings */
    if (termios_ok) {
        tcsetattr(tty_fd, TCSANOW, &old_attr);
    }

    /* Print a newline since the user's Enter was not echoed */
    fprintf(stdout, "\n");
    fflush(stdout);

    return line;
}
