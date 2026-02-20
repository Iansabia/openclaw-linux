/*
 * clawd-linux :: libclawd-core
 * str.c - Dynamic string utilities
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/str.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* ---- internal helpers --------------------------------------------------- */

static int str_grow(clawd_str_t *s, size_t needed)
{
    if (s->len + needed + 1 <= s->cap)
        return 0;

    size_t new_cap = s->cap ? s->cap : 16;
    while (new_cap < s->len + needed + 1)
        new_cap *= 2;

    char *tmp = realloc(s->data, new_cap);
    if (!tmp)
        return -1;

    s->data = tmp;
    s->cap  = new_cap;
    return 0;
}

/* ---- public API --------------------------------------------------------- */

clawd_str_t clawd_str_new(void)
{
    clawd_str_t s = {0};
    s.data = calloc(1, 16);
    if (s.data)
        s.cap = 16;
    return s;
}

clawd_str_t clawd_str_from(const char *src)
{
    clawd_str_t s = {0};
    if (!src)
        return clawd_str_new();

    size_t len = strlen(src);
    size_t cap = len + 1;
    if (cap < 16) cap = 16;

    s.data = malloc(cap);
    if (!s.data)
        return s;

    memcpy(s.data, src, len);
    s.data[len] = '\0';
    s.len = len;
    s.cap = cap;
    return s;
}

void clawd_str_free(clawd_str_t *s)
{
    if (!s) return;
    free(s->data);
    s->data = NULL;
    s->len  = 0;
    s->cap  = 0;
}

int clawd_str_append(clawd_str_t *s, const char *data, size_t len)
{
    if (!s || !data || len == 0)
        return 0;

    if (str_grow(s, len) != 0)
        return -1;

    memcpy(s->data + s->len, data, len);
    s->len += len;
    s->data[s->len] = '\0';
    return 0;
}

int clawd_str_append_cstr(clawd_str_t *s, const char *cstr)
{
    if (!cstr) return 0;
    return clawd_str_append(s, cstr, strlen(cstr));
}

int clawd_str_printf(clawd_str_t *s, const char *fmt, ...)
{
    if (!s || !fmt)
        return -1;

    va_list ap;

    /* First pass: measure how much space we need. */
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    if (n < 0)
        return -1;

    if (str_grow(s, (size_t)n) != 0)
        return -1;

    /* Second pass: actually write. */
    va_start(ap, fmt);
    vsnprintf(s->data + s->len, (size_t)n + 1, fmt, ap);
    va_end(ap);

    s->len += (size_t)n;
    return 0;
}

clawd_str_t clawd_str_dup(const clawd_str_t *s)
{
    if (!s || !s->data)
        return clawd_str_new();
    return clawd_str_from(s->data);
}

void clawd_str_trim(clawd_str_t *s)
{
    if (!s || !s->data || s->len == 0)
        return;

    /* trim leading */
    size_t start = 0;
    while (start < s->len && isspace((unsigned char)s->data[start]))
        start++;

    /* trim trailing */
    size_t end = s->len;
    while (end > start && isspace((unsigned char)s->data[end - 1]))
        end--;

    size_t new_len = end - start;
    if (start > 0)
        memmove(s->data, s->data + start, new_len);

    s->len = new_len;
    s->data[s->len] = '\0';
}

char **clawd_str_split(const char *s, char delim, int *count)
{
    if (count) *count = 0;
    if (!s) return NULL;

    /* Count parts. */
    int n = 1;
    for (const char *p = s; *p; p++) {
        if (*p == delim)
            n++;
    }

    char **parts = calloc((size_t)n, sizeof(char *));
    if (!parts)
        return NULL;

    int idx = 0;
    const char *start = s;
    for (const char *p = s; ; p++) {
        if (*p == delim || *p == '\0') {
            size_t seg_len = (size_t)(p - start);
            parts[idx] = malloc(seg_len + 1);
            if (!parts[idx]) {
                /* cleanup on failure */
                for (int j = 0; j < idx; j++)
                    free(parts[j]);
                free(parts);
                return NULL;
            }
            memcpy(parts[idx], start, seg_len);
            parts[idx][seg_len] = '\0';
            idx++;
            if (*p == '\0') break;
            start = p + 1;
        }
    }

    if (count) *count = n;
    return parts;
}

bool clawd_str_starts_with(const char *s, const char *prefix)
{
    if (!s || !prefix) return false;
    size_t plen = strlen(prefix);
    if (plen == 0) return true;
    return strncmp(s, prefix, plen) == 0;
}

bool clawd_str_ends_with(const char *s, const char *suffix)
{
    if (!s || !suffix) return false;
    size_t slen = strlen(s);
    size_t xlen = strlen(suffix);
    if (xlen == 0) return true;
    if (xlen > slen) return false;
    return memcmp(s + slen - xlen, suffix, xlen) == 0;
}

char *clawd_str_replace(const char *s, const char *old, const char *new_str)
{
    if (!s || !old || !new_str)
        return NULL;

    size_t old_len = strlen(old);
    size_t new_len = strlen(new_str);
    if (old_len == 0)
        return strdup(s);

    /* Count occurrences. */
    int occ = 0;
    const char *p = s;
    while ((p = strstr(p, old)) != NULL) {
        occ++;
        p += old_len;
    }

    size_t src_len = strlen(s);
    size_t result_len = src_len + (size_t)occ * (new_len - old_len);
    char *result = malloc(result_len + 1);
    if (!result)
        return NULL;

    char *dst = result;
    p = s;
    while (*p) {
        const char *match = strstr(p, old);
        if (!match) {
            /* copy the remainder */
            size_t tail = strlen(p);
            memcpy(dst, p, tail);
            dst += tail;
            break;
        }
        /* copy everything before the match */
        size_t before = (size_t)(match - p);
        memcpy(dst, p, before);
        dst += before;
        /* copy replacement */
        memcpy(dst, new_str, new_len);
        dst += new_len;
        p = match + old_len;
    }
    *dst = '\0';
    return result;
}
