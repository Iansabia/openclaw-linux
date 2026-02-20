/*
 * clawd-linux :: libclawd-terminal
 * test_terminal.c - Unit tests for ANSI, table, and progress APIs
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <clawd/ansi.h>
#include <clawd/table.h>
#include <clawd/progress.h>

/* ---- ANSI tests --------------------------------------------------------- */

static void test_ansi_strip_plain(void)
{
    /* Plain text with no ANSI codes should be unchanged. */
    char *out = clawd_ansi_strip("hello world");
    assert(out != NULL);
    assert(strcmp(out, "hello world") == 0);
    free(out);
    printf("  PASS: ansi_strip plain text\n");
}

static void test_ansi_strip_color(void)
{
    /* Color code ESC[31m should be removed. */
    char *out = clawd_ansi_strip("\033[31mred\033[0m");
    assert(out != NULL);
    assert(strcmp(out, "red") == 0);
    free(out);
    printf("  PASS: ansi_strip color codes\n");
}

static void test_ansi_strip_complex(void)
{
    /* Multiple SGR sequences */
    char *out = clawd_ansi_strip("\033[1;4;31mhello\033[0m \033[32mworld\033[0m");
    assert(out != NULL);
    assert(strcmp(out, "hello world") == 0);
    free(out);
    printf("  PASS: ansi_strip complex sequences\n");
}

static void test_ansi_strip_cursor(void)
{
    /* Cursor movement ESC[3A should be removed. */
    char *out = clawd_ansi_strip("before\033[3Aafter");
    assert(out != NULL);
    assert(strcmp(out, "beforeafter") == 0);
    free(out);
    printf("  PASS: ansi_strip cursor sequences\n");
}

static void test_ansi_strip_null(void)
{
    char *out = clawd_ansi_strip(NULL);
    assert(out == NULL);
    printf("  PASS: ansi_strip NULL input\n");
}

static void test_ansi_strip_empty(void)
{
    char *out = clawd_ansi_strip("");
    assert(out != NULL);
    assert(strcmp(out, "") == 0);
    free(out);
    printf("  PASS: ansi_strip empty string\n");
}

/* ---- ANSI strlen tests -------------------------------------------------- */

static void test_ansi_strlen_plain(void)
{
    assert(clawd_ansi_strlen("hello") == 5);
    printf("  PASS: ansi_strlen plain text\n");
}

static void test_ansi_strlen_color(void)
{
    assert(clawd_ansi_strlen("\033[31mred\033[0m") == 3);
    printf("  PASS: ansi_strlen with color codes\n");
}

static void test_ansi_strlen_empty(void)
{
    assert(clawd_ansi_strlen("") == 0);
    assert(clawd_ansi_strlen(NULL) == 0);
    printf("  PASS: ansi_strlen empty/NULL\n");
}

static void test_ansi_strlen_complex(void)
{
    /* Bold+underline+color "test" then reset = 4 visible chars */
    assert(clawd_ansi_strlen("\033[1;4;33mtest\033[0m") == 4);
    printf("  PASS: ansi_strlen complex\n");
}

/* ---- Table tests -------------------------------------------------------- */

static void test_table_basic(void)
{
    clawd_table_t *t = clawd_table_new(3);
    assert(t != NULL);

    clawd_table_set_header(t, "Name", "Age", "City");
    clawd_table_add_row(t, "Alice", "30", "London");
    clawd_table_add_row(t, "Bob", "25", "Paris");

    char *s = clawd_table_render_string(t);
    assert(s != NULL);

    /* The output should contain the cell values */
    assert(strstr(s, "Alice") != NULL);
    assert(strstr(s, "Bob") != NULL);
    assert(strstr(s, "London") != NULL);
    assert(strstr(s, "Paris") != NULL);
    assert(strstr(s, "Name") != NULL);
    assert(strstr(s, "Age") != NULL);
    assert(strstr(s, "City") != NULL);

    /* Check for box-drawing characters (UTF-8 encoded) */
    assert(strstr(s, "\xe2\x94\x8c") != NULL);  /* ┌ */
    assert(strstr(s, "\xe2\x94\x90") != NULL);  /* ┐ */
    assert(strstr(s, "\xe2\x94\x94") != NULL);  /* └ */
    assert(strstr(s, "\xe2\x94\x98") != NULL);  /* ┘ */
    assert(strstr(s, "\xe2\x94\x82") != NULL);  /* │ */
    assert(strstr(s, "\xe2\x94\x80") != NULL);  /* ─ */

    free(s);
    clawd_table_free(t);
    printf("  PASS: table basic rendering\n");
}

static void test_table_alignment(void)
{
    clawd_table_t *t = clawd_table_new(2);
    assert(t != NULL);

    clawd_table_set_header(t, "Item", "Price");
    clawd_table_set_align(t, 1, CLAWD_TABLE_ALIGN_RIGHT);
    clawd_table_add_row(t, "Apple", "1.50");
    clawd_table_add_row(t, "Banana", "0.75");

    char *s = clawd_table_render_string(t);
    assert(s != NULL);
    assert(strstr(s, "Apple") != NULL);
    assert(strstr(s, "Banana") != NULL);
    assert(strstr(s, "1.50") != NULL);
    assert(strstr(s, "0.75") != NULL);

    free(s);
    clawd_table_free(t);
    printf("  PASS: table alignment\n");
}

static void test_table_row_array(void)
{
    clawd_table_t *t = clawd_table_new(2);
    assert(t != NULL);

    clawd_table_set_header(t, "Key", "Value");
    const char *row1[] = {"foo", "bar"};
    const char *row2[] = {"baz", "qux"};
    clawd_table_add_row_array(t, row1, 2);
    clawd_table_add_row_array(t, row2, 2);

    char *s = clawd_table_render_string(t);
    assert(s != NULL);
    assert(strstr(s, "foo") != NULL);
    assert(strstr(s, "qux") != NULL);

    free(s);
    clawd_table_free(t);
    printf("  PASS: table row_array\n");
}

static void test_table_no_header(void)
{
    clawd_table_t *t = clawd_table_new(2);
    assert(t != NULL);

    /* No header set -- should still render data rows */
    clawd_table_add_row(t, "a", "b");

    char *s = clawd_table_render_string(t);
    assert(s != NULL);
    assert(strstr(s, "a") != NULL);
    assert(strstr(s, "b") != NULL);

    free(s);
    clawd_table_free(t);
    printf("  PASS: table no header\n");
}

static void test_table_empty(void)
{
    clawd_table_t *t = clawd_table_new(2);
    assert(t != NULL);

    clawd_table_set_header(t, "A", "B");
    /* No data rows */

    char *s = clawd_table_render_string(t);
    assert(s != NULL);
    assert(strstr(s, "A") != NULL);
    assert(strstr(s, "B") != NULL);

    free(s);
    clawd_table_free(t);
    printf("  PASS: table empty (header only)\n");
}

/* ---- Progress bar tests ------------------------------------------------- */

static void test_progress_create(void)
{
    /* We can at least verify creation and destruction work. */
    FILE *fp = fopen("/dev/null", "w");
    assert(fp != NULL);

    clawd_progress_t *p = clawd_progress_new(fp, 100, 40);
    assert(p != NULL);

    clawd_progress_update(p, 50);
    clawd_progress_finish(p);
    clawd_progress_free(p);

    fclose(fp);
    printf("  PASS: progress bar create/update/finish\n");
}

static void test_progress_null(void)
{
    clawd_progress_t *p = clawd_progress_new(NULL, 100, 40);
    assert(p == NULL);

    p = clawd_progress_new(stderr, 0, 40);
    assert(p == NULL);

    p = clawd_progress_new(stderr, 100, 0);
    assert(p == NULL);

    printf("  PASS: progress bar NULL/invalid args\n");
}

/* ---- Spinner tests ------------------------------------------------------ */

static void test_spinner_create(void)
{
    FILE *fp = fopen("/dev/null", "w");
    assert(fp != NULL);

    clawd_spinner_t *s = clawd_spinner_new(fp, "loading...");
    assert(s != NULL);

    clawd_spinner_free(s);
    fclose(fp);
    printf("  PASS: spinner create/free\n");
}

static void test_spinner_null(void)
{
    clawd_spinner_t *s = clawd_spinner_new(NULL, "test");
    assert(s == NULL);
    printf("  PASS: spinner NULL fp\n");
}

/* ---- Main --------------------------------------------------------------- */

int main(void)
{
    printf("=== libclawd-terminal tests ===\n");

    printf("\n-- ANSI strip --\n");
    test_ansi_strip_plain();
    test_ansi_strip_color();
    test_ansi_strip_complex();
    test_ansi_strip_cursor();
    test_ansi_strip_null();
    test_ansi_strip_empty();

    printf("\n-- ANSI strlen --\n");
    test_ansi_strlen_plain();
    test_ansi_strlen_color();
    test_ansi_strlen_empty();
    test_ansi_strlen_complex();

    printf("\n-- Table --\n");
    test_table_basic();
    test_table_alignment();
    test_table_row_array();
    test_table_no_header();
    test_table_empty();

    printf("\n-- Progress bar --\n");
    test_progress_create();
    test_progress_null();

    printf("\n-- Spinner --\n");
    test_spinner_create();
    test_spinner_null();

    printf("\n=== All libclawd-terminal tests passed ===\n");
    return 0;
}
