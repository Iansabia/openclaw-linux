/*
 * clawd-linux :: libclawd-terminal
 * ansi.h - ANSI escape code handling
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_ANSI_H
#define CLAWD_ANSI_H

#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Color codes -------------------------------------------------------- */

typedef enum {
    CLAWD_COLOR_RESET         = 0,
    CLAWD_COLOR_BLACK         = 30,
    CLAWD_COLOR_RED           = 31,
    CLAWD_COLOR_GREEN         = 32,
    CLAWD_COLOR_YELLOW        = 33,
    CLAWD_COLOR_BLUE          = 34,
    CLAWD_COLOR_MAGENTA       = 35,
    CLAWD_COLOR_CYAN          = 36,
    CLAWD_COLOR_WHITE         = 37,
    CLAWD_COLOR_BRIGHT_BLACK  = 90,
    CLAWD_COLOR_BRIGHT_RED    = 91,
    CLAWD_COLOR_BRIGHT_GREEN  = 92,
    CLAWD_COLOR_BRIGHT_YELLOW = 93,
    CLAWD_COLOR_BRIGHT_BLUE   = 94,
    CLAWD_COLOR_BRIGHT_MAGENTA= 95,
    CLAWD_COLOR_BRIGHT_CYAN   = 96,
    CLAWD_COLOR_BRIGHT_WHITE  = 97
} clawd_color_t;

/* ---- Style codes -------------------------------------------------------- */

typedef enum {
    CLAWD_STYLE_BOLD          = 1,
    CLAWD_STYLE_DIM           = 2,
    CLAWD_STYLE_ITALIC        = 3,
    CLAWD_STYLE_UNDERLINE     = 4,
    CLAWD_STYLE_BLINK         = 5,
    CLAWD_STYLE_REVERSE       = 7,
    CLAWD_STYLE_STRIKETHROUGH = 9
} clawd_style_t;

/* ---- API ---------------------------------------------------------------- */

/**
 * Check whether the given FILE stream is connected to a terminal.
 *
 * @param fp  File stream to check.
 * @return true if the stream is a TTY.
 */
bool clawd_ansi_is_tty(FILE *fp);

/**
 * Set the foreground color.
 *
 * @param fp  Output stream.
 * @param fg  Foreground color code.
 */
void clawd_ansi_color(FILE *fp, clawd_color_t fg);

/**
 * Set the background color.
 *
 * @param fp  Output stream.
 * @param bg  Background color code (will be offset to 40-47/100-107).
 */
void clawd_ansi_color_bg(FILE *fp, clawd_color_t bg);

/**
 * Apply a text style.
 *
 * @param fp     Output stream.
 * @param style  Style code.
 */
void clawd_ansi_style(FILE *fp, clawd_style_t style);

/**
 * Reset all attributes (color, style) to terminal defaults.
 *
 * @param fp  Output stream.
 */
void clawd_ansi_reset(FILE *fp);

/**
 * Set a 24-bit true-color foreground.
 *
 * @param fp  Output stream.
 * @param r   Red component (0-255).
 * @param g   Green component (0-255).
 * @param b   Blue component (0-255).
 */
void clawd_ansi_rgb(FILE *fp, int r, int g, int b);

/**
 * Move the cursor up by @p n lines.
 */
void clawd_ansi_cursor_up(FILE *fp, int n);

/**
 * Move the cursor down by @p n lines.
 */
void clawd_ansi_cursor_down(FILE *fp, int n);

/**
 * Save the current cursor position (DECSC).
 */
void clawd_ansi_cursor_save(FILE *fp);

/**
 * Restore the previously saved cursor position (DECRC).
 */
void clawd_ansi_cursor_restore(FILE *fp);

/**
 * Clear the current line.
 */
void clawd_ansi_clear_line(FILE *fp);

/**
 * Clear the entire screen and move cursor to top-left.
 */
void clawd_ansi_clear_screen(FILE *fp);

/**
 * Return a copy of @p s with all ANSI escape sequences removed.
 *
 * The caller must free the returned string.
 * Returns NULL on allocation failure.
 */
char *clawd_ansi_strip(const char *s);

/**
 * Compute the visible (display) length of @p s, ignoring ANSI escape sequences.
 *
 * @param s  The string to measure.
 * @return Number of visible characters.
 */
size_t clawd_ansi_strlen(const char *s);

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_ANSI_H */
