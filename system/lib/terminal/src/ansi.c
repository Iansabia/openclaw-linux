/*
 * kelp-linux :: libkelp-terminal
 * ansi.c - ANSI escape code implementation
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/ansi.h>

#include <ctype.h>
#include <locale.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>

/* ---- TTY detection ------------------------------------------------------ */

bool kelp_ansi_is_tty(FILE *fp)
{
    if (!fp) return false;
    return isatty(fileno(fp)) != 0;
}

/* ---- Color and style ---------------------------------------------------- */

void kelp_ansi_color(FILE *fp, kelp_color_t fg)
{
    if (!fp || !kelp_ansi_is_tty(fp)) return;
    if (fg == KELP_COLOR_RESET) {
        fprintf(fp, "\033[0m");
    } else {
        fprintf(fp, "\033[%dm", (int)fg);
    }
}

void kelp_ansi_color_bg(FILE *fp, kelp_color_t bg)
{
    if (!fp || !kelp_ansi_is_tty(fp)) return;
    if (bg == KELP_COLOR_RESET) {
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

void kelp_ansi_style(FILE *fp, kelp_style_t style)
{
    if (!fp || !kelp_ansi_is_tty(fp)) return;
    fprintf(fp, "\033[%dm", (int)style);
}

void kelp_ansi_reset(FILE *fp)
{
    if (!fp || !kelp_ansi_is_tty(fp)) return;
    fprintf(fp, "\033[0m");
}

void kelp_ansi_rgb(FILE *fp, int r, int g, int b)
{
    if (!fp || !kelp_ansi_is_tty(fp)) return;
    /* Clamp values to 0-255 */
    if (r < 0) r = 0; else if (r > 255) r = 255;
    if (g < 0) g = 0; else if (g > 255) g = 255;
    if (b < 0) b = 0; else if (b > 255) b = 255;
    fprintf(fp, "\033[38;2;%d;%d;%dm", r, g, b);
}

/* ---- Cursor control ----------------------------------------------------- */

void kelp_ansi_cursor_up(FILE *fp, int n)
{
    if (!fp || !kelp_ansi_is_tty(fp) || n <= 0) return;
    fprintf(fp, "\033[%dA", n);
}

void kelp_ansi_cursor_down(FILE *fp, int n)
{
    if (!fp || !kelp_ansi_is_tty(fp) || n <= 0) return;
    fprintf(fp, "\033[%dB", n);
}

void kelp_ansi_cursor_left(FILE *fp, int n)
{
    if (!fp || !kelp_ansi_is_tty(fp) || n <= 0) return;
    fprintf(fp, "\033[%dD", n);
}

void kelp_ansi_cursor_right(FILE *fp, int n)
{
    if (!fp || !kelp_ansi_is_tty(fp) || n <= 0) return;
    fprintf(fp, "\033[%dC", n);
}

void kelp_ansi_cursor_col(FILE *fp, int col)
{
    if (!fp || !kelp_ansi_is_tty(fp) || col <= 0) return;
    fprintf(fp, "\033[%dG", col);
}

void kelp_ansi_cursor_hide(FILE *fp)
{
    if (!fp || !kelp_ansi_is_tty(fp)) return;
    fprintf(fp, "\033[?25l");
}

void kelp_ansi_cursor_show(FILE *fp)
{
    if (!fp || !kelp_ansi_is_tty(fp)) return;
    fprintf(fp, "\033[?25h");
}

void kelp_ansi_cursor_save(FILE *fp)
{
    if (!fp || !kelp_ansi_is_tty(fp)) return;
    fprintf(fp, "\033[s");
}

void kelp_ansi_cursor_restore(FILE *fp)
{
    if (!fp || !kelp_ansi_is_tty(fp)) return;
    fprintf(fp, "\033[u");
}

void kelp_ansi_clear_line(FILE *fp)
{
    if (!fp || !kelp_ansi_is_tty(fp)) return;
    fprintf(fp, "\033[2K\r");
}

void kelp_ansi_clear_screen(FILE *fp)
{
    if (!fp || !kelp_ansi_is_tty(fp)) return;
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

char *kelp_ansi_strip(const char *s)
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

/*
 * Ensure the C locale is initialized for multibyte/wide-char conversion.
 * Called once via a simple flag; a harmless double-init of setlocale is
 * acceptable.
 */
static void ensure_locale_init(void)
{
    static volatile int initialized = 0;
    if (!initialized) {
        setlocale(LC_CTYPE, "");
        initialized = 1;
    }
}

/*
 * Decode a single UTF-8 codepoint starting at *p.
 * Sets *bytes_consumed to the number of bytes read.
 * Returns the Unicode codepoint, or (wchar_t)-1 on error.
 */
static wchar_t decode_utf8(const char *p, int *bytes_consumed)
{
    unsigned char c = (unsigned char)*p;

    if (c < 0x80) {
        *bytes_consumed = 1;
        return (wchar_t)c;
    } else if ((c & 0xE0) == 0xC0) {
        if (((unsigned char)p[1] & 0xC0) != 0x80) {
            *bytes_consumed = 1;
            return (wchar_t)-1;
        }
        *bytes_consumed = 2;
        return (wchar_t)(((c & 0x1F) << 6) |
                         ((unsigned char)p[1] & 0x3F));
    } else if ((c & 0xF0) == 0xE0) {
        if (((unsigned char)p[1] & 0xC0) != 0x80 ||
            ((unsigned char)p[2] & 0xC0) != 0x80) {
            *bytes_consumed = 1;
            return (wchar_t)-1;
        }
        *bytes_consumed = 3;
        return (wchar_t)(((c & 0x0F) << 12) |
                         (((unsigned char)p[1] & 0x3F) << 6) |
                         ((unsigned char)p[2] & 0x3F));
    } else if ((c & 0xF8) == 0xF0) {
        if (((unsigned char)p[1] & 0xC0) != 0x80 ||
            ((unsigned char)p[2] & 0xC0) != 0x80 ||
            ((unsigned char)p[3] & 0xC0) != 0x80) {
            *bytes_consumed = 1;
            return (wchar_t)-1;
        }
        *bytes_consumed = 4;
        return (wchar_t)(((c & 0x07) << 18) |
                         (((unsigned char)p[1] & 0x3F) << 12) |
                         (((unsigned char)p[2] & 0x3F) << 6) |
                         ((unsigned char)p[3] & 0x3F));
    }

    /* Invalid leading byte */
    *bytes_consumed = 1;
    return (wchar_t)-1;
}

size_t kelp_ansi_strlen(const char *s)
{
    if (!s) return 0;

    ensure_locale_init();

    size_t len = 0;
    const char *p = s;

    while (*p) {
        if (*p == '\033') {
            p = skip_ansi(p);
        } else {
            /*
             * Decode the UTF-8 codepoint and use wcwidth() to get the
             * display width.  CJK characters return 2, ASCII returns 1,
             * combining marks return 0.
             */
            int consumed = 1;
            wchar_t wc = decode_utf8(p, &consumed);

            if (wc == (wchar_t)-1) {
                /* Invalid byte -- skip it, count as 1 column */
                len++;
                p++;
            } else {
                int w = wcwidth(wc);
                if (w < 0) {
                    /* Non-printable character (e.g. control chars) -- 0 width */
                    w = 0;
                }
                len += (size_t)w;
                p += consumed;
            }
        }
    }

    return len;
}
