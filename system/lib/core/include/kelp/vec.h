/*
 * kelp-linux :: libkelp-core
 * vec.h - Generic dynamic array (macro-based, header-only)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_VEC_H
#define KELP_VEC_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * KELP_VEC_DEFINE(name, type)
 *
 * Expands to a complete typed dynamic-array implementation:
 *
 *   typedef struct { type *data; size_t len; size_t cap; } kelp_##name##_vec_t;
 *
 *   kelp_##name##_vec_t  kelp_##name##_vec_new(void);
 *   void                  kelp_##name##_vec_free(kelp_##name##_vec_t *v);
 *   int                   kelp_##name##_vec_push(kelp_##name##_vec_t *v, type val);
 *   type                  kelp_##name##_vec_pop(kelp_##name##_vec_t *v);
 *   type                  kelp_##name##_vec_get(const kelp_##name##_vec_t *v, size_t i);
 *   void                  kelp_##name##_vec_clear(kelp_##name##_vec_t *v);
 *
 * All functions are declared `static inline` so that each translation unit
 * that includes this header gets its own copy, avoiding linker collisions.
 */
#define KELP_VEC_DEFINE(name, type)                                          \
                                                                              \
typedef struct {                                                              \
    type  *data;                                                              \
    size_t len;                                                               \
    size_t cap;                                                               \
} kelp_##name##_vec_t;                                                       \
                                                                              \
static inline kelp_##name##_vec_t kelp_##name##_vec_new(void)               \
{                                                                             \
    kelp_##name##_vec_t v;                                                   \
    v.data = NULL;                                                            \
    v.len  = 0;                                                               \
    v.cap  = 0;                                                               \
    return v;                                                                 \
}                                                                             \
                                                                              \
static inline void kelp_##name##_vec_free(kelp_##name##_vec_t *v)           \
{                                                                             \
    if (v) {                                                                  \
        free(v->data);                                                        \
        v->data = NULL;                                                       \
        v->len  = 0;                                                          \
        v->cap  = 0;                                                          \
    }                                                                         \
}                                                                             \
                                                                              \
static inline int kelp_##name##_vec_push(kelp_##name##_vec_t *v, type val)  \
{                                                                             \
    if (!v) return -1;                                                        \
    if (v->len >= v->cap) {                                                   \
        size_t new_cap = v->cap ? v->cap * 2 : 8;                            \
        type *tmp = (type *)realloc(v->data, new_cap * sizeof(type));         \
        if (!tmp) return -1;                                                  \
        v->data = tmp;                                                        \
        v->cap  = new_cap;                                                    \
    }                                                                         \
    v->data[v->len++] = val;                                                  \
    return 0;                                                                 \
}                                                                             \
                                                                              \
static inline type kelp_##name##_vec_pop(kelp_##name##_vec_t *v)            \
{                                                                             \
    type zero;                                                                \
    memset(&zero, 0, sizeof(type));                                           \
    if (!v || v->len == 0) return zero;                                       \
    return v->data[--v->len];                                                 \
}                                                                             \
                                                                              \
static inline type kelp_##name##_vec_get(                                    \
        const kelp_##name##_vec_t *v, size_t i)                              \
{                                                                             \
    type zero;                                                                \
    memset(&zero, 0, sizeof(type));                                           \
    if (!v || i >= v->len) return zero;                                       \
    return v->data[i];                                                        \
}                                                                             \
                                                                              \
static inline void kelp_##name##_vec_clear(kelp_##name##_vec_t *v)          \
{                                                                             \
    if (v) v->len = 0;                                                        \
}

/* ---- Pre-defined vector types ------------------------------------------- */

KELP_VEC_DEFINE(str, char *)
KELP_VEC_DEFINE(int, int)

#ifdef __cplusplus
}
#endif

#endif /* KELP_VEC_H */
