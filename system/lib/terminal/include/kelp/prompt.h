/*
 * kelp-linux :: libkelp-terminal
 * prompt.h - Reusable terminal prompt helpers
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_PROMPT_H
#define KELP_PROMPT_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Simple yes/no confirmation prompt.
 *
 * Prints @p message followed by [Y/n] or [y/N] depending on the default.
 * Reads a single character from stdin.  Enter accepts the default.
 *
 * @param message      Prompt message to display.
 * @param default_yes  If true, the default answer is yes (shown as [Y/n]).
 * @return true if the user answered yes.
 */
bool kelp_prompt_confirm(const char *message, bool default_yes);

/**
 * Choose from a numbered list of options.
 *
 * Prints @p message, then a numbered list starting at 1.  Reads a number
 * from stdin and validates the range.
 *
 * @param message  Prompt message to display.
 * @param options  Array of option strings.
 * @param count    Number of elements in @p options.
 * @return 0-based index of the selected option, or -1 on error/EOF.
 */
int kelp_prompt_select(const char *message, const char **options, int count);

/**
 * Read a line of text with an optional default value.
 *
 * Prints @p message.  If @p default_value is non-NULL and non-empty, it is
 * shown in brackets and returned when the user presses Enter without typing
 * anything.
 *
 * @param message        Prompt message to display.
 * @param default_value  Default value (may be NULL).
 * @return Allocated string (caller must free), or NULL on error/EOF.
 */
char *kelp_prompt_input(const char *message, const char *default_value);

/**
 * Read a password without echoing characters.
 *
 * Uses termios to disable echo while reading.  A trailing newline is
 * printed after the user presses Enter so the terminal looks tidy.
 *
 * @param message  Prompt message to display.
 * @return Allocated string (caller must free), or NULL on error/EOF.
 */
char *kelp_prompt_password(const char *message);

#ifdef __cplusplus
}
#endif

#endif /* KELP_PROMPT_H */
