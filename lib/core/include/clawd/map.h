/*
 * clawd-linux :: libclawd-core
 * map.h - Hash map (string keys, void* values)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_MAP_H
#define CLAWD_MAP_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque hash-map handle. */
typedef struct clawd_map clawd_map_t;

/** Iterator state for walking every entry in the map. */
typedef struct {
    const char *key;
    void       *value;
    /* private -- do not touch */
    size_t      _idx;
} clawd_map_iter_t;

/** Create a new, empty hash map. Returns NULL on allocation failure. */
clawd_map_t *clawd_map_new(void);

/** Free the map and all owned key copies. Values are NOT freed. */
void clawd_map_free(clawd_map_t *m);

/**
 * Insert or update a key/value pair.
 * The key is copied internally; the caller retains ownership of `value`.
 * Returns 0 on success, -1 on allocation failure.
 */
int clawd_map_set(clawd_map_t *m, const char *key, void *value);

/** Look up a key. Returns the value pointer, or NULL if not found. */
void *clawd_map_get(clawd_map_t *m, const char *key);

/** Return true if the key exists in the map. */
bool clawd_map_has(clawd_map_t *m, const char *key);

/**
 * Delete a key from the map.
 * Returns 0 if the key was found and removed, -1 if not found.
 * The stored value is NOT freed.
 */
int clawd_map_del(clawd_map_t *m, const char *key);

/** Return the number of entries currently stored. */
size_t clawd_map_size(const clawd_map_t *m);

/**
 * Advance the iterator to the next entry.
 *
 * Usage:
 *     clawd_map_iter_t it = {0};
 *     while (clawd_map_iter(m, &it)) {
 *         printf("%s -> %p\n", it.key, it.value);
 *     }
 *
 * Returns true while there are more entries, false when done.
 */
bool clawd_map_iter(clawd_map_t *m, clawd_map_iter_t *it);

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_MAP_H */
