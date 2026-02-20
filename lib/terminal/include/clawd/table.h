/*
 * clawd-linux :: libclawd-terminal
 * table.h - Table formatting with Unicode box-drawing characters
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_TABLE_H
#define CLAWD_TABLE_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Alignment ---------------------------------------------------------- */

typedef enum {
    CLAWD_TABLE_ALIGN_LEFT,
    CLAWD_TABLE_ALIGN_RIGHT,
    CLAWD_TABLE_ALIGN_CENTER
} clawd_table_align_t;

/* ---- Opaque handle ------------------------------------------------------ */

typedef struct clawd_table clawd_table_t;

/* ---- API ---------------------------------------------------------------- */

/**
 * Create a new table with @p cols columns.
 *
 * @param cols  Number of columns (must be > 0).
 * @return Table handle, or NULL on allocation failure.
 */
clawd_table_t *clawd_table_new(int cols);

/**
 * Free a table and all associated memory.
 *
 * @param t  Table handle (may be NULL).
 */
void clawd_table_free(clawd_table_t *t);

/**
 * Set the header row.
 *
 * Accepts exactly @p cols NUL-terminated strings as varargs.
 * The strings are copied internally.
 *
 * @param t  Table handle.
 * @param ... const char* values, one per column.
 */
void clawd_table_set_header(clawd_table_t *t, ...);

/**
 * Set the alignment for a specific column.
 *
 * @param t      Table handle.
 * @param col    Column index (0-based).
 * @param align  Alignment mode.
 */
void clawd_table_set_align(clawd_table_t *t, int col, clawd_table_align_t align);

/**
 * Add a data row.
 *
 * Accepts exactly @p cols NUL-terminated strings as varargs.
 * The strings are copied internally.
 *
 * @param t  Table handle.
 * @param ... const char* values, one per column.
 */
void clawd_table_add_row(clawd_table_t *t, ...);

/**
 * Add a data row from an array of strings.
 *
 * @param t      Table handle.
 * @param cols   Array of NUL-terminated strings.
 * @param count  Number of elements in @p cols (should match table column count).
 */
void clawd_table_add_row_array(clawd_table_t *t, const char **cols, int count);

/**
 * Render the table to a FILE stream.
 *
 * @param t   Table handle.
 * @param fp  Output stream.
 */
void clawd_table_render(clawd_table_t *t, FILE *fp);

/**
 * Render the table to a dynamically allocated string.
 *
 * The caller must free the returned string.
 * Returns NULL on allocation failure.
 *
 * @param t  Table handle.
 * @return Rendered table string.
 */
char *clawd_table_render_string(clawd_table_t *t);

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_TABLE_H */
