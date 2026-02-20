/*
 * clawd-linux :: libclawd-core
 * str.h - Dynamic string utilities
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_STR_H
#define CLAWD_STR_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Dynamic string type.
 *
 * `data` is always NUL-terminated when the string is valid.
 * `len` does NOT include the NUL terminator.
 * `cap` is the total allocated size (includes room for NUL).
 */
typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} clawd_str_t;

/** Create an empty dynamic string. */
clawd_str_t clawd_str_new(void);

/** Create a dynamic string from a C string (deep copy). */
clawd_str_t clawd_str_from(const char *s);

/** Free all memory owned by the string and zero the struct. */
void clawd_str_free(clawd_str_t *s);

/** Append `len` bytes from `data` to the string. */
int clawd_str_append(clawd_str_t *s, const char *data, size_t len);

/** Append a NUL-terminated C string. */
int clawd_str_append_cstr(clawd_str_t *s, const char *cstr);

/** Append a printf-formatted string. */
int clawd_str_printf(clawd_str_t *s, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/** Duplicate a dynamic string (deep copy). */
clawd_str_t clawd_str_dup(const clawd_str_t *s);

/** Trim leading and trailing whitespace in place. */
void clawd_str_trim(clawd_str_t *s);

/**
 * Split a C string on a delimiter character.
 *
 * Returns a malloc'd array of malloc'd strings. The caller must free every
 * element and then the array itself.  `*count` is set to the number of parts.
 */
char **clawd_str_split(const char *s, char delim, int *count);

/** Return true if `s` starts with `prefix`. */
bool clawd_str_starts_with(const char *s, const char *prefix);

/** Return true if `s` ends with `suffix`. */
bool clawd_str_ends_with(const char *s, const char *suffix);

/**
 * Replace every occurrence of `old` with `new_str` in `s`.
 *
 * Returns a newly malloc'd string; the caller must free it.
 * Returns NULL on allocation failure.
 */
char *clawd_str_replace(const char *s, const char *old, const char *new_str);

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_STR_H */
