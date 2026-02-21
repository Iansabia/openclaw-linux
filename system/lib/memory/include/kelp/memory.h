/*
 * kelp-linux :: libkelp-memory
 * memory.h - Knowledge store with hybrid BM25 + vector search
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_MEMORY_H
#define KELP_MEMORY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque handle to the memory/knowledge store. */
typedef struct kelp_memory kelp_memory_t;

/** A single entry in the memory store. */
typedef struct kelp_memory_entry {
    int64_t  id;
    char    *content;
    char    *source;        /* file path, URL, or "user" */
    char    *category;      /* "code", "doc", "chat", "note" */
    float   *embedding;     /* vector embedding (may be NULL) */
    int      embedding_dim;
    double   score;         /* search relevance score */
    int64_t  created_at;
    int64_t  updated_at;
} kelp_memory_entry_t;

/** Options controlling hybrid search behaviour. */
typedef struct kelp_search_opts {
    const char *query;
    int         limit;          /* max results (default 10) */
    float       min_score;      /* minimum relevance threshold */
    const char *category;       /* filter by category (NULL = all) */
    bool        use_vectors;    /* use vector similarity */
    bool        use_bm25;       /* use BM25 text search */
    float       vector_weight;  /* weight for vector scores (0-1) */
    float       bm25_weight;    /* weight for BM25 scores (0-1) */
    float       mmr_lambda;     /* MMR diversity param (0=diverse, 1=relevant) */
} kelp_search_opts_t;

/**
 * Open (or create) a memory store backed by a SQLite database.
 *
 * @param db_path  Path to the SQLite file, or ":memory:" for in-memory.
 * @return Handle on success, NULL on failure.
 */
kelp_memory_t *kelp_memory_open(const char *db_path);

/**
 * Close the memory store and release all associated resources.
 */
void kelp_memory_close(kelp_memory_t *mem);

/**
 * Add a new entry to the store.
 *
 * @return The entry id (>0) on success, -1 on error.
 */
int64_t kelp_memory_add(kelp_memory_t *mem, const char *content,
                          const char *source, const char *category);

/**
 * Update the content of an existing entry (also bumps updated_at).
 *
 * @return 0 on success, -1 on error.
 */
int kelp_memory_update(kelp_memory_t *mem, int64_t id,
                         const char *content);

/**
 * Delete an entry by id.
 *
 * @return 0 on success, -1 on error.
 */
int kelp_memory_delete(kelp_memory_t *mem, int64_t id);

/**
 * Retrieve a single entry by id.
 *
 * @param entry  Output struct; string fields are heap-allocated
 *               and must be freed via kelp_memory_entry_free().
 * @return 0 on success, -1 on error or not found.
 */
int kelp_memory_get(kelp_memory_t *mem, int64_t id,
                      kelp_memory_entry_t *entry);

/**
 * Hybrid search (BM25 + vector similarity with MMR reranking).
 *
 * @param opts     Search parameters.
 * @param results  On success, set to a malloc'd array of entries.
 * @param count    On success, set to the number of entries.
 * @return 0 on success, -1 on error.
 *
 * Caller must free results via kelp_memory_entry_array_free().
 */
int kelp_memory_search(kelp_memory_t *mem,
                         const kelp_search_opts_t *opts,
                         kelp_memory_entry_t **results, int *count);

/**
 * Free a single entry's heap-allocated fields (content, source,
 * category, embedding).  Does NOT free the entry struct itself.
 */
void kelp_memory_entry_free(kelp_memory_entry_t *entry);

/**
 * Free an array of entries returned by kelp_memory_search().
 */
void kelp_memory_entry_array_free(kelp_memory_entry_t *entries, int count);

#ifdef __cplusplus
}
#endif

#endif /* KELP_MEMORY_H */
