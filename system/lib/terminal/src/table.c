/*
 * kelp-linux :: libkelp-terminal
 * table.c - Table formatting with Unicode box-drawing characters
 *
 * Box-drawing characters used:
 *   ┌─┬─┐   top border
 *   │ │ │   cell separators
 *   ├─┼─┤   header separator / row separator
 *   └─┴─┘   bottom border
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/table.h>
#include <kelp/ansi.h>

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* ---- Internal types ----------------------------------------------------- */

typedef struct kelp_table_row {
    char **cells;
    struct kelp_table_row *next;
} kelp_table_row_t;

struct kelp_table {
    int                  cols;
    kelp_table_align_t *aligns;
    char               **header;
    kelp_table_row_t   *rows_head;
    kelp_table_row_t   *rows_tail;
    int                  row_count;
};

/* ---- Helpers ------------------------------------------------------------ */

static char *str_dup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s);
    char *d = (char *)malloc(len + 1);
    if (d) memcpy(d, s, len + 1);
    return d;
}

/*
 * Visible length of a string, ignoring ANSI escape codes.
 * This is a simple implementation that counts codepoints, not
 * wide-character display widths.
 */
static size_t visible_len(const char *s)
{
    return kelp_ansi_strlen(s);
}

/* Append a string to a dynamic buffer */
typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} strbuf_t;

static void strbuf_init(strbuf_t *sb)
{
    sb->data = NULL;
    sb->len  = 0;
    sb->cap  = 0;
}

static void strbuf_ensure(strbuf_t *sb, size_t extra)
{
    size_t need = sb->len + extra + 1;
    if (need <= sb->cap) return;
    size_t newcap = sb->cap ? sb->cap * 2 : 256;
    while (newcap < need) newcap *= 2;
    char *p = (char *)realloc(sb->data, newcap);
    if (!p) return;  /* best-effort */
    sb->data = p;
    sb->cap  = newcap;
}

static void strbuf_append(strbuf_t *sb, const char *s)
{
    size_t slen = strlen(s);
    strbuf_ensure(sb, slen);
    memcpy(sb->data + sb->len, s, slen);
    sb->len += slen;
    sb->data[sb->len] = '\0';
}

static void strbuf_append_char(strbuf_t *sb, char c)
{
    strbuf_ensure(sb, 1);
    sb->data[sb->len++] = c;
    sb->data[sb->len] = '\0';
}

static void strbuf_append_repeat(strbuf_t *sb, const char *s, int count)
{
    for (int i = 0; i < count; i++) {
        strbuf_append(sb, s);
    }
}

/* ---- Table creation / destruction --------------------------------------- */

kelp_table_t *kelp_table_new(int cols)
{
    if (cols <= 0) return NULL;

    kelp_table_t *t = (kelp_table_t *)calloc(1, sizeof(*t));
    if (!t) return NULL;

    t->cols = cols;
    t->aligns = (kelp_table_align_t *)calloc((size_t)cols, sizeof(kelp_table_align_t));
    if (!t->aligns) {
        free(t);
        return NULL;
    }

    return t;
}

static void free_row(kelp_table_row_t *row, int cols)
{
    if (!row) return;
    if (row->cells) {
        for (int i = 0; i < cols; i++) {
            free(row->cells[i]);
        }
        free(row->cells);
    }
    free(row);
}

void kelp_table_free(kelp_table_t *t)
{
    if (!t) return;

    if (t->header) {
        for (int i = 0; i < t->cols; i++) {
            free(t->header[i]);
        }
        free(t->header);
    }

    kelp_table_row_t *row = t->rows_head;
    while (row) {
        kelp_table_row_t *next = row->next;
        free_row(row, t->cols);
        row = next;
    }

    free(t->aligns);
    free(t);
}

/* ---- Header / alignment / row ------------------------------------------- */

void kelp_table_set_header(kelp_table_t *t, ...)
{
    if (!t) return;

    /* Free existing header if any */
    if (t->header) {
        for (int i = 0; i < t->cols; i++) {
            free(t->header[i]);
        }
        free(t->header);
    }

    t->header = (char **)calloc((size_t)t->cols, sizeof(char *));
    if (!t->header) return;

    va_list ap;
    va_start(ap, t);
    for (int i = 0; i < t->cols; i++) {
        const char *s = va_arg(ap, const char *);
        t->header[i] = str_dup(s ? s : "");
    }
    va_end(ap);
}

void kelp_table_set_align(kelp_table_t *t, int col, kelp_table_align_t align)
{
    if (!t || col < 0 || col >= t->cols) return;
    t->aligns[col] = align;
}

void kelp_table_add_row(kelp_table_t *t, ...)
{
    if (!t) return;

    kelp_table_row_t *row = (kelp_table_row_t *)calloc(1, sizeof(*row));
    if (!row) return;

    row->cells = (char **)calloc((size_t)t->cols, sizeof(char *));
    if (!row->cells) {
        free(row);
        return;
    }

    va_list ap;
    va_start(ap, t);
    for (int i = 0; i < t->cols; i++) {
        const char *s = va_arg(ap, const char *);
        row->cells[i] = str_dup(s ? s : "");
    }
    va_end(ap);

    row->next = NULL;
    if (t->rows_tail) {
        t->rows_tail->next = row;
    } else {
        t->rows_head = row;
    }
    t->rows_tail = row;
    t->row_count++;
}

void kelp_table_add_row_array(kelp_table_t *t, const char **cols, int count)
{
    if (!t || !cols) return;

    kelp_table_row_t *row = (kelp_table_row_t *)calloc(1, sizeof(*row));
    if (!row) return;

    row->cells = (char **)calloc((size_t)t->cols, sizeof(char *));
    if (!row->cells) {
        free(row);
        return;
    }

    for (int i = 0; i < t->cols; i++) {
        const char *s = (i < count && cols[i]) ? cols[i] : "";
        row->cells[i] = str_dup(s);
    }

    row->next = NULL;
    if (t->rows_tail) {
        t->rows_tail->next = row;
    } else {
        t->rows_head = row;
    }
    t->rows_tail = row;
    t->row_count++;
}

/* ---- Rendering ---------------------------------------------------------- */

/*
 * Compute column widths based on header and all rows.
 * Returns a malloc'd array of `cols` ints.
 */
static int *compute_widths(const kelp_table_t *t)
{
    int *widths = (int *)calloc((size_t)t->cols, sizeof(int));
    if (!widths) return NULL;

    /* Header widths */
    if (t->header) {
        for (int i = 0; i < t->cols; i++) {
            int w = (int)visible_len(t->header[i]);
            if (w > widths[i]) widths[i] = w;
        }
    }

    /* Row widths */
    for (kelp_table_row_t *row = t->rows_head; row; row = row->next) {
        for (int i = 0; i < t->cols; i++) {
            int w = (int)visible_len(row->cells[i]);
            if (w > widths[i]) widths[i] = w;
        }
    }

    return widths;
}

/*
 * Render a horizontal border line.
 *   left:  "┌" or "├" or "└"
 *   mid:   "┬" or "┼" or "┴"
 *   right: "┐" or "┤" or "┘"
 *   fill:  "─"
 */
static void render_border(strbuf_t *sb, const int *widths, int cols,
                           const char *left, const char *mid,
                           const char *right, const char *fill)
{
    strbuf_append(sb, left);
    for (int i = 0; i < cols; i++) {
        /* width + 2 for padding spaces on each side */
        strbuf_append_repeat(sb, fill, widths[i] + 2);
        if (i < cols - 1) {
            strbuf_append(sb, mid);
        }
    }
    strbuf_append(sb, right);
    strbuf_append_char(sb, '\n');
}

/*
 * Render a row of cells with "│" separators and appropriate alignment.
 */
static void render_cells(strbuf_t *sb, char **cells, const int *widths,
                          const kelp_table_align_t *aligns, int cols)
{
    /* "│" */
    strbuf_append(sb, "\xe2\x94\x82");
    for (int i = 0; i < cols; i++) {
        const char *cell = cells[i] ? cells[i] : "";
        int vlen = (int)visible_len(cell);
        int pad  = widths[i] - vlen;
        if (pad < 0) pad = 0;

        strbuf_append_char(sb, ' ');

        switch (aligns[i]) {
        case KELP_TABLE_ALIGN_RIGHT: {
            for (int p = 0; p < pad; p++) strbuf_append_char(sb, ' ');
            strbuf_append(sb, cell);
            break;
        }
        case KELP_TABLE_ALIGN_CENTER: {
            int left_pad = pad / 2;
            int right_pad = pad - left_pad;
            for (int p = 0; p < left_pad; p++) strbuf_append_char(sb, ' ');
            strbuf_append(sb, cell);
            for (int p = 0; p < right_pad; p++) strbuf_append_char(sb, ' ');
            break;
        }
        case KELP_TABLE_ALIGN_LEFT:
        default: {
            strbuf_append(sb, cell);
            for (int p = 0; p < pad; p++) strbuf_append_char(sb, ' ');
            break;
        }
        }

        strbuf_append_char(sb, ' ');
        /* "│" */
        strbuf_append(sb, "\xe2\x94\x82");
    }
    strbuf_append_char(sb, '\n');
}

static char *render_to_string(kelp_table_t *t)
{
    if (!t || t->cols <= 0) return NULL;

    int *widths = compute_widths(t);
    if (!widths) return NULL;

    strbuf_t sb;
    strbuf_init(&sb);

    /* Top border: ┌─┬─┐ */
    render_border(&sb, widths, t->cols,
                  "\xe2\x94\x8c", "\xe2\x94\xac",
                  "\xe2\x94\x90", "\xe2\x94\x80");

    /* Header row */
    if (t->header) {
        render_cells(&sb, t->header, widths, t->aligns, t->cols);
        /* Header separator: ├─┼─┤ */
        render_border(&sb, widths, t->cols,
                      "\xe2\x94\x9c", "\xe2\x94\xbc",
                      "\xe2\x94\xa4", "\xe2\x94\x80");
    }

    /* Data rows */
    for (kelp_table_row_t *row = t->rows_head; row; row = row->next) {
        render_cells(&sb, row->cells, widths, t->aligns, t->cols);
    }

    /* Bottom border: └─┴─┘ */
    render_border(&sb, widths, t->cols,
                  "\xe2\x94\x94", "\xe2\x94\xb4",
                  "\xe2\x94\x98", "\xe2\x94\x80");

    free(widths);
    return sb.data;
}

void kelp_table_render(kelp_table_t *t, FILE *fp)
{
    if (!t || !fp) return;

    char *s = render_to_string(t);
    if (s) {
        fputs(s, fp);
        free(s);
    }
}

char *kelp_table_render_string(kelp_table_t *t)
{
    return render_to_string(t);
}
