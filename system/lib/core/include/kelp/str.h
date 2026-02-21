/*
 * kelp-linux :: libkelp-core
 * str.h - Dynamic string utilities
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_STR_H
#define KELP_STR_H

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
} kelp_str_t;

/** Create an empty dynamic string. */
kelp_str_t kelp_str_new(void);

/** Create a dynamic string from a C string (deep copy). */
kelp_str_t kelp_str_from(const char *s);

/** Free all memory owned by the string and zero the struct. */
void kelp_str_free(kelp_str_t *s);

/** Append `len` bytes from `data` to the string. */
int kelp_str_append(kelp_str_t *s, const char *data, size_t len);

/** Append a NUL-terminated C string. */
int kelp_str_append_cstr(kelp_str_t *s, const char *cstr);

/** Append a printf-formatted string. */
int kelp_str_printf(kelp_str_t *s, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/** Duplicate a dynamic string (deep copy). */
kelp_str_t kelp_str_dup(const kelp_str_t *s);

/** Trim leading and trailing whitespace in place. */
void kelp_str_trim(kelp_str_t *s);

/**
 * Split a C string on a delimiter character.
 *
 * Returns a malloc'd array of malloc'd strings. The caller must free every
 * element and then the array itself.  `*count` is set to the number of parts.
 */
char **kelp_str_split(const char *s, char delim, int *count);

/** Return true if `s` starts with `prefix`. */
bool kelp_str_starts_with(const char *s, const char *prefix);

/** Return true if `s` ends with `suffix`. */
bool kelp_str_ends_with(const char *s, const char *suffix);

/**
 * Replace every occurrence of `old` with `new_str` in `s`.
 *
 * Returns a newly malloc'd string; the caller must free it.
 * Returns NULL on allocation failure.
 */
char *kelp_str_replace(const char *s, const char *old, const char *new_str);

#ifdef __cplusplus
}
#endif

#endif /* KELP_STR_H */
