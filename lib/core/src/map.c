/*
 * clawd-linux :: libclawd-core
 * map.c - Hash map with FNV-1a / open addressing / linear probing
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/map.h>

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* ---- constants ---------------------------------------------------------- */

#define MAP_INITIAL_CAP  16
#define MAP_LOAD_FACTOR  0.75

/* Sentinel markers for entry state. */
#define ENTRY_EMPTY      0
#define ENTRY_ALIVE      1
#define ENTRY_TOMBSTONE  2

/* ---- internal types ----------------------------------------------------- */

typedef struct {
    char  *key;     /* heap-allocated copy (NULL when empty/tombstone) */
    void  *value;
    int    state;   /* ENTRY_EMPTY | ENTRY_ALIVE | ENTRY_TOMBSTONE */
} map_entry_t;

struct clawd_map {
    map_entry_t *entries;
    size_t       cap;
    size_t       size;    /* live entries */
    size_t       filled;  /* live + tombstones (governs resize) */
};

/* ---- FNV-1a hash -------------------------------------------------------- */

static uint64_t fnv1a(const char *key)
{
    uint64_t h = 14695981039346656037ULL;
    for (const unsigned char *p = (const unsigned char *)key; *p; p++) {
        h ^= (uint64_t)*p;
        h *= 1099511628211ULL;
    }
    return h;
}

/* ---- internal helpers --------------------------------------------------- */

static size_t probe(size_t hash, size_t cap)
{
    return hash & (cap - 1);  /* cap is always a power of two */
}

/**
 * Find the slot for `key`.
 *
 * If the key already exists, returns its index and sets `*found` = true.
 * Otherwise returns the index of the first available slot (empty or tombstone)
 * and sets `*found` = false.
 */
static size_t map_find_slot(const map_entry_t *entries, size_t cap,
                            const char *key, bool *found)
{
    uint64_t h = fnv1a(key);
    size_t idx = probe(h, cap);
    size_t first_tombstone = SIZE_MAX;

    for (size_t i = 0; i < cap; i++) {
        size_t slot = (idx + i) & (cap - 1);
        const map_entry_t *e = &entries[slot];

        if (e->state == ENTRY_EMPTY) {
            *found = false;
            return (first_tombstone != SIZE_MAX) ? first_tombstone : slot;
        }
        if (e->state == ENTRY_TOMBSTONE) {
            if (first_tombstone == SIZE_MAX)
                first_tombstone = slot;
            continue;
        }
        /* ENTRY_ALIVE */
        if (strcmp(e->key, key) == 0) {
            *found = true;
            return slot;
        }
    }

    /* Table is full of tombstones (should never happen with resize). */
    *found = false;
    return (first_tombstone != SIZE_MAX) ? first_tombstone : 0;
}

static int map_resize(clawd_map_t *m, size_t new_cap)
{
    map_entry_t *new_entries = calloc(new_cap, sizeof(map_entry_t));
    if (!new_entries)
        return -1;

    /* Re-insert every live entry. */
    for (size_t i = 0; i < m->cap; i++) {
        map_entry_t *e = &m->entries[i];
        if (e->state != ENTRY_ALIVE)
            continue;

        bool found;
        size_t slot = map_find_slot(new_entries, new_cap, e->key, &found);
        new_entries[slot].key   = e->key;   /* transfer ownership */
        new_entries[slot].value = e->value;
        new_entries[slot].state = ENTRY_ALIVE;
    }

    free(m->entries);
    m->entries = new_entries;
    m->cap     = new_cap;
    m->filled  = m->size;  /* tombstones are gone */
    return 0;
}

/* ---- public API --------------------------------------------------------- */

clawd_map_t *clawd_map_new(void)
{
    clawd_map_t *m = calloc(1, sizeof(clawd_map_t));
    if (!m) return NULL;

    m->entries = calloc(MAP_INITIAL_CAP, sizeof(map_entry_t));
    if (!m->entries) {
        free(m);
        return NULL;
    }
    m->cap    = MAP_INITIAL_CAP;
    m->size   = 0;
    m->filled = 0;
    return m;
}

void clawd_map_free(clawd_map_t *m)
{
    if (!m) return;
    for (size_t i = 0; i < m->cap; i++) {
        if (m->entries[i].state == ENTRY_ALIVE)
            free(m->entries[i].key);
    }
    free(m->entries);
    free(m);
}

int clawd_map_set(clawd_map_t *m, const char *key, void *value)
{
    if (!m || !key)
        return -1;

    /* Resize if needed (based on filled slots, which includes tombstones). */
    if ((double)(m->filled + 1) > (double)m->cap * MAP_LOAD_FACTOR) {
        if (map_resize(m, m->cap * 2) != 0)
            return -1;
    }

    bool found;
    size_t slot = map_find_slot(m->entries, m->cap, key, &found);

    if (found) {
        /* Update existing entry. */
        m->entries[slot].value = value;
        return 0;
    }

    /* New entry. */
    bool was_empty = (m->entries[slot].state == ENTRY_EMPTY);
    m->entries[slot].key   = strdup(key);
    if (!m->entries[slot].key)
        return -1;

    m->entries[slot].value = value;
    m->entries[slot].state = ENTRY_ALIVE;
    m->size++;
    if (was_empty)
        m->filled++;
    /* If it was a tombstone, filled count is already accounted for. */
    return 0;
}

void *clawd_map_get(clawd_map_t *m, const char *key)
{
    if (!m || !key)
        return NULL;

    bool found;
    size_t slot = map_find_slot(m->entries, m->cap, key, &found);
    return found ? m->entries[slot].value : NULL;
}

bool clawd_map_has(clawd_map_t *m, const char *key)
{
    if (!m || !key)
        return false;

    bool found;
    map_find_slot(m->entries, m->cap, key, &found);
    return found;
}

int clawd_map_del(clawd_map_t *m, const char *key)
{
    if (!m || !key)
        return -1;

    bool found;
    size_t slot = map_find_slot(m->entries, m->cap, key, &found);
    if (!found)
        return -1;

    free(m->entries[slot].key);
    m->entries[slot].key   = NULL;
    m->entries[slot].value = NULL;
    m->entries[slot].state = ENTRY_TOMBSTONE;
    m->size--;
    /* `filled` stays the same (tombstone still occupies a slot). */
    return 0;
}

size_t clawd_map_size(const clawd_map_t *m)
{
    return m ? m->size : 0;
}

bool clawd_map_iter(clawd_map_t *m, clawd_map_iter_t *it)
{
    if (!m || !it)
        return false;

    while (it->_idx < m->cap) {
        size_t i = it->_idx++;
        if (m->entries[i].state == ENTRY_ALIVE) {
            it->key   = m->entries[i].key;
            it->value = m->entries[i].value;
            return true;
        }
    }
    return false;
}
