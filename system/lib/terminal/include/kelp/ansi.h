/*
 * kelp-linux :: libkelp-terminal
 * ansi.h - ANSI escape code handling
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_ANSI_H
#define KELP_ANSI_H

#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Color codes -------------------------------------------------------- */

typedef enum {
    KELP_COLOR_RESET         = 0,
    KELP_COLOR_BLACK         = 30,
    KELP_COLOR_RED           = 31,
    KELP_COLOR_GREEN         = 32,
    KELP_COLOR_YELLOW        = 33,
    KELP_COLOR_BLUE          = 34,
    KELP_COLOR_MAGENTA       = 35,
    KELP_COLOR_CYAN          = 36,
    KELP_COLOR_WHITE         = 37,
    KELP_COLOR_BRIGHT_BLACK  = 90,
    KELP_COLOR_BRIGHT_RED    = 91,
    KELP_COLOR_BRIGHT_GREEN  = 92,
    KELP_COLOR_BRIGHT_YELLOW = 93,
    KELP_COLOR_BRIGHT_BLUE   = 94,
    KELP_COLOR_BRIGHT_MAGENTA= 95,
    KELP_COLOR_BRIGHT_CYAN   = 96,
    KELP_COLOR_BRIGHT_WHITE  = 97
} kelp_color_t;

/* ---- Style codes -------------------------------------------------------- */

typedef enum {
    KELP_STYLE_BOLD          = 1,
    KELP_STYLE_DIM           = 2,
    KELP_STYLE_ITALIC        = 3,
    KELP_STYLE_UNDERLINE     = 4,
    KELP_STYLE_BLINK         = 5,
    KELP_STYLE_REVERSE       = 7,
    KELP_STYLE_STRIKETHROUGH = 9
} kelp_style_t;

/* ---- API ---------------------------------------------------------------- */

/**
 * Check whether the given FILE stream is connected to a terminal.
 *
 * @param fp  File stream to check.
 * @return true if the stream is a TTY.
 */
bool kelp_ansi_is_tty(FILE *fp);

/**
 * Set the foreground color.
 *
 * @param fp  Output stream.
 * @param fg  Foreground color code.
 */
void kelp_ansi_color(FILE *fp, kelp_color_t fg);

/**
 * Set the background color.
 *
 * @param fp  Output stream.
 * @param bg  Background color code (will be offset to 40-47/100-107).
 */
void kelp_ansi_color_bg(FILE *fp, kelp_color_t bg);

/**
 * Apply a text style.
 *
 * @param fp     Output stream.
 * @param style  Style code.
 */
void kelp_ansi_style(FILE *fp, kelp_style_t style);

/**
 * Reset all attributes (color, style) to terminal defaults.
 *
 * @param fp  Output stream.
 */
void kelp_ansi_reset(FILE *fp);

/**
 * Set a 24-bit true-color foreground.
 *
 * @param fp  Output stream.
 * @param r   Red component (0-255).
 * @param g   Green component (0-255).
 * @param b   Blue component (0-255).
 */
void kelp_ansi_rgb(FILE *fp, int r, int g, int b);

/**
 * Move the cursor up by @p n lines.
 */
void kelp_ansi_cursor_up(FILE *fp, int n);

/**
 * Move the cursor down by @p n lines.
 */
void kelp_ansi_cursor_down(FILE *fp, int n);

/**
 * Move the cursor left by @p n columns.
 */
void kelp_ansi_cursor_left(FILE *fp, int n);

/**
 * Move the cursor right by @p n columns.
 */
void kelp_ansi_cursor_right(FILE *fp, int n);

/**
 * Move the cursor to an absolute column position.
 *
 * @param fp   Output stream.
 * @param col  Column number (1-based).
 */
void kelp_ansi_cursor_col(FILE *fp, int col);

/**
 * Hide the cursor.
 */
void kelp_ansi_cursor_hide(FILE *fp);

/**
 * Show the cursor.
 */
void kelp_ansi_cursor_show(FILE *fp);

/**
 * Save the current cursor position (DECSC).
 */
void kelp_ansi_cursor_save(FILE *fp);

/**
 * Restore the previously saved cursor position (DECRC).
 */
void kelp_ansi_cursor_restore(FILE *fp);

/**
 * Clear the current line.
 */
void kelp_ansi_clear_line(FILE *fp);

/**
 * Clear the entire screen and move cursor to top-left.
 */
void kelp_ansi_clear_screen(FILE *fp);

/**
 * Return a copy of @p s with all ANSI escape sequences removed.
 *
 * The caller must free the returned string.
 * Returns NULL on allocation failure.
 */
char *kelp_ansi_strip(const char *s);

/**
 * Compute the visible (display) length of @p s, ignoring ANSI escape
 * sequences.  Uses wcwidth() to correctly account for wide characters
 * (CJK ideographs take 2 columns) and combining marks (0 columns).
 *
 * @param s  The string to measure.
 * @return Number of terminal display columns.
 */
size_t kelp_ansi_strlen(const char *s);

#ifdef __cplusplus
}
#endif

#endif /* KELP_ANSI_H */
