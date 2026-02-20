/*
 * clawd-linux :: libclawd-terminal
 * ansi.c - ANSI escape code implementation
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/ansi.h>

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- TTY detection ------------------------------------------------------ */

bool clawd_ansi_is_tty(FILE *fp)
{
    if (!fp) return false;
    return isatty(fileno(fp)) != 0;
}

/* ---- Color and style ---------------------------------------------------- */

void clawd_ansi_color(FILE *fp, clawd_color_t fg)
{
    if (!fp || !clawd_ansi_is_tty(fp)) return;
    if (fg == CLAWD_COLOR_RESET) {
        fprintf(fp, "\033[0m");
    } else {
        fprintf(fp, "\033[%dm", (int)fg);
    }
}

void clawd_ansi_color_bg(FILE *fp, clawd_color_t bg)
{
    if (!fp || !clawd_ansi_is_tty(fp)) return;
    if (bg == CLAWD_COLOR_RESET) {
        fprintf(fp, "\033[0m");
        return;
    }
    /*
     * Foreground colors are 30-37 (normal) and 90-97 (bright).
     * Background equivalents are 40-47 and 100-107 respectively.
     */
    int code = (int)bg;
    if (code >= 30 && code <= 37) {
        code += 10;  /* 40-47 */
    } else if (code >= 90 && code <= 97) {
        code += 10;  /* 100-107 */
    }
    fprintf(fp, "\033[%dm", code);
}

void clawd_ansi_style(FILE *fp, clawd_style_t style)
{
    if (!fp || !clawd_ansi_is_tty(fp)) return;
    fprintf(fp, "\033[%dm", (int)style);
}

void clawd_ansi_reset(FILE *fp)
{
    if (!fp || !clawd_ansi_is_tty(fp)) return;
    fprintf(fp, "\033[0m");
}

void clawd_ansi_rgb(FILE *fp, int r, int g, int b)
{
    if (!fp || !clawd_ansi_is_tty(fp)) return;
    /* Clamp values to 0-255 */
    if (r < 0) r = 0; else if (r > 255) r = 255;
    if (g < 0) g = 0; else if (g > 255) g = 255;
    if (b < 0) b = 0; else if (b > 255) b = 255;
    fprintf(fp, "\033[38;2;%d;%d;%dm", r, g, b);
}

/* ---- Cursor control ----------------------------------------------------- */

void clawd_ansi_cursor_up(FILE *fp, int n)
{
    if (!fp || !clawd_ansi_is_tty(fp) || n <= 0) return;
    fprintf(fp, "\033[%dA", n);
}

void clawd_ansi_cursor_down(FILE *fp, int n)
{
    if (!fp || !clawd_ansi_is_tty(fp) || n <= 0) return;
    fprintf(fp, "\033[%dB", n);
}

void clawd_ansi_cursor_save(FILE *fp)
{
    if (!fp || !clawd_ansi_is_tty(fp)) return;
    fprintf(fp, "\033[s");
}

void clawd_ansi_cursor_restore(FILE *fp)
{
    if (!fp || !clawd_ansi_is_tty(fp)) return;
    fprintf(fp, "\033[u");
}

void clawd_ansi_clear_line(FILE *fp)
{
    if (!fp || !clawd_ansi_is_tty(fp)) return;
    fprintf(fp, "\033[2K\r");
}

void clawd_ansi_clear_screen(FILE *fp)
{
    if (!fp || !clawd_ansi_is_tty(fp)) return;
    fprintf(fp, "\033[2J\033[H");
}

/* ---- ANSI stripping ----------------------------------------------------- */

/*
 * ANSI escape sequences we handle:
 *   ESC [ <params> <final byte>         CSI sequences
 *   ESC ] <string> (BEL | ESC \)        OSC sequences
 *   ESC <single byte in 0x40-0x5F>      two-character sequences
 */
static const char *skip_ansi(const char *p)
{
    if (*p != '\033') return p;

    p++;  /* skip ESC */

    if (*p == '[') {
        /* CSI sequence: ESC [ ... <final byte 0x40-0x7E> */
        p++;
        while (*p && (unsigned char)*p < 0x40) p++;
        if (*p) p++;  /* skip final byte */
    } else if (*p == ']') {
        /* OSC sequence: ESC ] ... (BEL | ESC \) */
        p++;
        while (*p && *p != '\007') {
            if (*p == '\033' && *(p + 1) == '\\') {
                p += 2;
                break;
            }
            p++;
        }
        if (*p == '\007') p++;
    } else if (*p >= 0x40 && *p <= 0x5F) {
        /* Two-character sequence */
        p++;
    }

    return p;
}

char *clawd_ansi_strip(const char *s)
{
    if (!s) return NULL;

    size_t slen = strlen(s);
    char *out = (char *)malloc(slen + 1);
    if (!out) return NULL;

    size_t oi = 0;
    const char *p = s;

    while (*p) {
        if (*p == '\033') {
            p = skip_ansi(p);
        } else {
            out[oi++] = *p++;
        }
    }

    out[oi] = '\0';
    return out;
}

size_t clawd_ansi_strlen(const char *s)
{
    if (!s) return 0;

    size_t len = 0;
    const char *p = s;

    while (*p) {
        if (*p == '\033') {
            p = skip_ansi(p);
        } else {
            /* Handle multi-byte UTF-8: count codepoints, not bytes. */
            unsigned char c = (unsigned char)*p;
            if (c < 0x80) {
                len++;
                p++;
            } else if ((c & 0xE0) == 0xC0) {
                len++;
                p += 2;
            } else if ((c & 0xF0) == 0xE0) {
                len++;
                p += 3;
            } else if ((c & 0xF8) == 0xF0) {
                len++;
                p += 4;
            } else {
                /* Invalid byte, skip */
                len++;
                p++;
            }
        }
    }

    return len;
}
