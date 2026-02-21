/*
 * kelp-linux :: libkelp-core
 * map.h - Hash map (string keys, void* values)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_MAP_H
#define KELP_MAP_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque hash-map handle. */
typedef struct kelp_map kelp_map_t;

/** Iterator state for walking every entry in the map. */
typedef struct {
    const char *key;
    void       *value;
    /* private -- do not touch */
    size_t      _idx;
} kelp_map_iter_t;

/** Create a new, empty hash map. Returns NULL on allocation failure. */
kelp_map_t *kelp_map_new(void);

/** Free the map and all owned key copies. Values are NOT freed. */
void kelp_map_free(kelp_map_t *m);

/**
 * Insert or update a key/value pair.
 * The key is copied internally; the caller retains ownership of `value`.
 * Returns 0 on success, -1 on allocation failure.
 */
int kelp_map_set(kelp_map_t *m, const char *key, void *value);

/** Look up a key. Returns the value pointer, or NULL if not found. */
void *kelp_map_get(kelp_map_t *m, const char *key);

/** Return true if the key exists in the map. */
bool kelp_map_has(kelp_map_t *m, const char *key);

/**
 * Delete a key from the map.
 * Returns 0 if the key was found and removed, -1 if not found.
 * The stored value is NOT freed.
 */
int kelp_map_del(kelp_map_t *m, const char *key);

/** Return the number of entries currently stored. */
size_t kelp_map_size(const kelp_map_t *m);

/**
 * Advance the iterator to the next entry.
 *
 * Usage:
 *     kelp_map_iter_t it = {0};
 *     while (kelp_map_iter(m, &it)) {
 *         printf("%s -> %p\n", it.key, it.value);
 *     }
 *
 * Returns true while there are more entries, false when done.
 */
bool kelp_map_iter(kelp_map_t *m, kelp_map_iter_t *it);

#ifdef __cplusplus
}
#endif

#endif /* KELP_MAP_H */
