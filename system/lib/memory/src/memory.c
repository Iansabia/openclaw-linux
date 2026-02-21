/*
 * kelp-linux :: libkelp-memory
 * memory.c - SQLite-backed knowledge store with hybrid search
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/memory.h>
#include <kelp/log.h>

#include <sqlite3.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <dlfcn.h>

/* ----------------------------------------------------------------------- */
/* Internal structure                                                       */
/* ----------------------------------------------------------------------- */

struct kelp_memory {
    sqlite3        *db;
    sqlite3_stmt   *stmt_insert;
    sqlite3_stmt   *stmt_update;
    sqlite3_stmt   *stmt_delete;
    sqlite3_stmt   *stmt_get;
    sqlite3_stmt   *stmt_fts_search;
    bool            has_fts5;
    bool            has_vec;
    void           *vec_handle;       /* dlopen handle for sqlite-vec */
};

/* ----------------------------------------------------------------------- */
/* Forward declarations for static helpers                                  */
/* ----------------------------------------------------------------------- */

static int  memory_init_schema(kelp_memory_t *mem);
static int  memory_try_load_vec(kelp_memory_t *mem);
static int  memory_prepare_statements(kelp_memory_t *mem);
static void memory_finalize_statements(kelp_memory_t *mem);
static char *memory_strdup(const char *s);
static int64_t memory_now(void);

/* Cosine similarity between two float vectors of the same dimension. */
static double cosine_similarity(const float *a, const float *b, int dim);

/* MMR reranking helper. */
static void mmr_rerank(kelp_memory_entry_t *entries, int count,
                       int desired, float lambda);

/* ----------------------------------------------------------------------- */
/* Public API                                                               */
/* ----------------------------------------------------------------------- */

kelp_memory_t *
kelp_memory_open(const char *db_path)
{
    if (!db_path) return NULL;

    kelp_memory_t *mem = calloc(1, sizeof(*mem));
    if (!mem) return NULL;

    int rc = sqlite3_open(db_path, &mem->db);
    if (rc != SQLITE_OK) {
        KELP_ERROR("sqlite3_open(%s): %s", db_path, sqlite3_errmsg(mem->db));
        sqlite3_close(mem->db);
        free(mem);
        return NULL;
    }

    /* Enable WAL mode for better concurrency. */
    sqlite3_exec(mem->db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(mem->db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL);

    /* Try to load the sqlite-vec extension for vector search. */
    memory_try_load_vec(mem);

    if (memory_init_schema(mem) != 0) {
        KELP_ERROR("failed to initialise memory schema");
        kelp_memory_close(mem);
        return NULL;
    }

    if (memory_prepare_statements(mem) != 0) {
        KELP_ERROR("failed to prepare memory statements");
        kelp_memory_close(mem);
        return NULL;
    }

    return mem;
}

void
kelp_memory_close(kelp_memory_t *mem)
{
    if (!mem) return;

    memory_finalize_statements(mem);

    if (mem->db) {
        sqlite3_close(mem->db);
        mem->db = NULL;
    }

    if (mem->vec_handle) {
        dlclose(mem->vec_handle);
        mem->vec_handle = NULL;
    }

    free(mem);
}

int64_t
kelp_memory_add(kelp_memory_t *mem, const char *content,
                  const char *source, const char *category)
{
    if (!mem || !content) return -1;

    int64_t now = memory_now();

    sqlite3_reset(mem->stmt_insert);
    sqlite3_bind_text(mem->stmt_insert, 1, content,  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(mem->stmt_insert, 2, source   ? source   : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(mem->stmt_insert, 3, category ? category : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(mem->stmt_insert, 4, now);
    sqlite3_bind_int64(mem->stmt_insert, 5, now);

    int rc = sqlite3_step(mem->stmt_insert);
    if (rc != SQLITE_DONE) {
        KELP_ERROR("memory_add: %s", sqlite3_errmsg(mem->db));
        return -1;
    }

    int64_t id = sqlite3_last_insert_rowid(mem->db);

    /* Sync FTS5 if available. */
    if (mem->has_fts5) {
        char sql[512];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO entries_fts(rowid, content, source) "
                 "VALUES(%lld, ?, ?);",
                 (long long)id);
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(mem->db, sql, -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, content, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, source ? source : "", -1, SQLITE_TRANSIENT);
            sqlite3_step(st);
            sqlite3_finalize(st);
        }
    }

    return id;
}

int
kelp_memory_update(kelp_memory_t *mem, int64_t id, const char *content)
{
    if (!mem || !content) return -1;

    int64_t now = memory_now();

    sqlite3_reset(mem->stmt_update);
    sqlite3_bind_text(mem->stmt_update, 1, content, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(mem->stmt_update, 2, now);
    sqlite3_bind_int64(mem->stmt_update, 3, id);

    int rc = sqlite3_step(mem->stmt_update);
    if (rc != SQLITE_DONE) {
        KELP_ERROR("memory_update: %s", sqlite3_errmsg(mem->db));
        return -1;
    }

    if (sqlite3_changes(mem->db) == 0) return -1;

    /* Update FTS5. */
    if (mem->has_fts5) {
        /* Read current source for the FTS sync. */
        sqlite3_stmt *rd = NULL;
        const char *source = "";
        if (sqlite3_prepare_v2(mem->db,
                "SELECT source FROM entries WHERE id = ?;",
                -1, &rd, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(rd, 1, id);
            if (sqlite3_step(rd) == SQLITE_ROW) {
                source = (const char *)sqlite3_column_text(rd, 0);
            }
        }

        /* Delete old FTS row and insert updated one. */
        char dsql[256];
        snprintf(dsql, sizeof(dsql),
                 "DELETE FROM entries_fts WHERE rowid = %lld;",
                 (long long)id);
        sqlite3_exec(mem->db, dsql, NULL, NULL, NULL);

        char isql[512];
        snprintf(isql, sizeof(isql),
                 "INSERT INTO entries_fts(rowid, content, source) "
                 "VALUES(%lld, ?, ?);",
                 (long long)id);
        sqlite3_stmt *ist = NULL;
        if (sqlite3_prepare_v2(mem->db, isql, -1, &ist, NULL) == SQLITE_OK) {
            sqlite3_bind_text(ist, 1, content, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ist, 2, source,  -1, SQLITE_TRANSIENT);
            sqlite3_step(ist);
            sqlite3_finalize(ist);
        }

        if (rd) sqlite3_finalize(rd);
    }

    return 0;
}

int
kelp_memory_delete(kelp_memory_t *mem, int64_t id)
{
    if (!mem) return -1;

    /* Delete from FTS5 first. */
    if (mem->has_fts5) {
        char sql[256];
        snprintf(sql, sizeof(sql),
                 "DELETE FROM entries_fts WHERE rowid = %lld;",
                 (long long)id);
        sqlite3_exec(mem->db, sql, NULL, NULL, NULL);
    }

    /* Delete from vec table if available. */
    if (mem->has_vec) {
        char sql[256];
        snprintf(sql, sizeof(sql),
                 "DELETE FROM vec_entries WHERE id = %lld;",
                 (long long)id);
        sqlite3_exec(mem->db, sql, NULL, NULL, NULL);
    }

    sqlite3_reset(mem->stmt_delete);
    sqlite3_bind_int64(mem->stmt_delete, 1, id);

    int rc = sqlite3_step(mem->stmt_delete);
    if (rc != SQLITE_DONE) {
        KELP_ERROR("memory_delete: %s", sqlite3_errmsg(mem->db));
        return -1;
    }

    return (sqlite3_changes(mem->db) > 0) ? 0 : -1;
}

int
kelp_memory_get(kelp_memory_t *mem, int64_t id,
                  kelp_memory_entry_t *entry)
{
    if (!mem || !entry) return -1;

    memset(entry, 0, sizeof(*entry));

    sqlite3_reset(mem->stmt_get);
    sqlite3_bind_int64(mem->stmt_get, 1, id);

    int rc = sqlite3_step(mem->stmt_get);
    if (rc != SQLITE_ROW) {
        return -1;
    }

    entry->id         = sqlite3_column_int64(mem->stmt_get, 0);
    entry->content    = memory_strdup((const char *)sqlite3_column_text(mem->stmt_get, 1));
    entry->source     = memory_strdup((const char *)sqlite3_column_text(mem->stmt_get, 2));
    entry->category   = memory_strdup((const char *)sqlite3_column_text(mem->stmt_get, 3));
    entry->created_at = sqlite3_column_int64(mem->stmt_get, 4);
    entry->updated_at = sqlite3_column_int64(mem->stmt_get, 5);
    entry->embedding  = NULL;
    entry->embedding_dim = 0;
    entry->score      = 0.0;

    return 0;
}

int
kelp_memory_search(kelp_memory_t *mem,
                     const kelp_search_opts_t *opts,
                     kelp_memory_entry_t **results, int *count)
{
    if (!mem || !opts || !results || !count) return -1;

    *results = NULL;
    *count   = 0;

    const char *query = opts->query;
    if (!query || !*query) return -1;

    int limit = (opts->limit > 0) ? opts->limit : 10;

    /* We fetch a larger candidate set, then apply MMR reranking. */
    int fetch_limit = limit * 3;
    if (fetch_limit < 30) fetch_limit = 30;

    /*
     * Allocate a working buffer for candidate entries.
     * We will fill this from BM25/FTS5 results.
     */
    kelp_memory_entry_t *candidates = NULL;
    int n_candidates = 0;

    /* ---- BM25 / FTS5 search ---- */
    if (opts->use_bm25 && mem->has_fts5) {
        char sql[1024];
        if (opts->category && opts->category[0]) {
            snprintf(sql, sizeof(sql),
                     "SELECT e.id, e.content, e.source, e.category, "
                     "       e.created_at, e.updated_at, "
                     "       bm25(entries_fts, 1.0, 0.5) AS rank "
                     "FROM entries_fts f "
                     "JOIN entries e ON e.id = f.rowid "
                     "WHERE entries_fts MATCH ? AND e.category = ? "
                     "ORDER BY rank "
                     "LIMIT %d;", fetch_limit);
        } else {
            snprintf(sql, sizeof(sql),
                     "SELECT e.id, e.content, e.source, e.category, "
                     "       e.created_at, e.updated_at, "
                     "       bm25(entries_fts, 1.0, 0.5) AS rank "
                     "FROM entries_fts f "
                     "JOIN entries e ON e.id = f.rowid "
                     "WHERE entries_fts MATCH ? "
                     "ORDER BY rank "
                     "LIMIT %d;", fetch_limit);
        }

        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(mem->db, sql, -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, query, -1, SQLITE_TRANSIENT);
            if (opts->category && opts->category[0]) {
                sqlite3_bind_text(st, 2, opts->category, -1, SQLITE_TRANSIENT);
            }

            /* Count results first pass is not needed; just grow the array. */
            int cap = 32;
            candidates = calloc((size_t)cap, sizeof(*candidates));
            if (!candidates) {
                sqlite3_finalize(st);
                return -1;
            }

            while (sqlite3_step(st) == SQLITE_ROW) {
                if (n_candidates >= cap) {
                    cap *= 2;
                    kelp_memory_entry_t *tmp = realloc(candidates,
                            (size_t)cap * sizeof(*candidates));
                    if (!tmp) break;
                    candidates = tmp;
                }

                kelp_memory_entry_t *e = &candidates[n_candidates];
                memset(e, 0, sizeof(*e));
                e->id         = sqlite3_column_int64(st, 0);
                e->content    = memory_strdup((const char *)sqlite3_column_text(st, 1));
                e->source     = memory_strdup((const char *)sqlite3_column_text(st, 2));
                e->category   = memory_strdup((const char *)sqlite3_column_text(st, 3));
                e->created_at = sqlite3_column_int64(st, 4);
                e->updated_at = sqlite3_column_int64(st, 5);
                /* BM25 scores from SQLite are negative (lower = better).
                 * Negate to get a positive score where higher = better. */
                e->score      = -sqlite3_column_double(st, 6);
                e->embedding  = NULL;
                e->embedding_dim = 0;
                n_candidates++;
            }

            sqlite3_finalize(st);
        }
    }

    /* If no BM25 results (or BM25 not requested) and no vector search,
     * fall back to a simple LIKE search. */
    if (n_candidates == 0 && !opts->use_vectors) {
        char sql[1024];
        if (opts->category && opts->category[0]) {
            snprintf(sql, sizeof(sql),
                     "SELECT id, content, source, category, "
                     "       created_at, updated_at "
                     "FROM entries "
                     "WHERE content LIKE '%%' || ? || '%%' "
                     "  AND category = ? "
                     "LIMIT %d;", fetch_limit);
        } else {
            snprintf(sql, sizeof(sql),
                     "SELECT id, content, source, category, "
                     "       created_at, updated_at "
                     "FROM entries "
                     "WHERE content LIKE '%%' || ? || '%%' "
                     "LIMIT %d;", fetch_limit);
        }

        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(mem->db, sql, -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, query, -1, SQLITE_TRANSIENT);
            if (opts->category && opts->category[0]) {
                sqlite3_bind_text(st, 2, opts->category, -1, SQLITE_TRANSIENT);
            }

            int cap = 32;
            candidates = calloc((size_t)cap, sizeof(*candidates));
            if (!candidates) {
                sqlite3_finalize(st);
                return -1;
            }

            while (sqlite3_step(st) == SQLITE_ROW) {
                if (n_candidates >= cap) {
                    cap *= 2;
                    kelp_memory_entry_t *tmp = realloc(candidates,
                            (size_t)cap * sizeof(*candidates));
                    if (!tmp) break;
                    candidates = tmp;
                }

                kelp_memory_entry_t *e = &candidates[n_candidates];
                memset(e, 0, sizeof(*e));
                e->id         = sqlite3_column_int64(st, 0);
                e->content    = memory_strdup((const char *)sqlite3_column_text(st, 1));
                e->source     = memory_strdup((const char *)sqlite3_column_text(st, 2));
                e->category   = memory_strdup((const char *)sqlite3_column_text(st, 3));
                e->created_at = sqlite3_column_int64(st, 4);
                e->updated_at = sqlite3_column_int64(st, 5);
                e->score      = 1.0;   /* simple match, uniform score */
                e->embedding  = NULL;
                e->embedding_dim = 0;
                n_candidates++;
            }

            sqlite3_finalize(st);
        }
    }

    /* Filter by min_score. */
    if (opts->min_score > 0.0f && n_candidates > 0) {
        int write_idx = 0;
        for (int i = 0; i < n_candidates; i++) {
            if (candidates[i].score >= (double)opts->min_score) {
                if (write_idx != i) {
                    candidates[write_idx] = candidates[i];
                }
                write_idx++;
            } else {
                kelp_memory_entry_free(&candidates[i]);
            }
        }
        n_candidates = write_idx;
    }

    /* MMR reranking for diversity. */
    float lambda = opts->mmr_lambda;
    if (lambda <= 0.0f) lambda = 1.0f;  /* default: pure relevance */
    if (n_candidates > limit) {
        mmr_rerank(candidates, n_candidates, limit, lambda);
        /* Free entries beyond the desired limit. */
        for (int i = limit; i < n_candidates; i++) {
            kelp_memory_entry_free(&candidates[i]);
        }
        n_candidates = limit;
    }

    *results = candidates;
    *count   = n_candidates;
    return 0;
}

void
kelp_memory_entry_free(kelp_memory_entry_t *entry)
{
    if (!entry) return;
    free(entry->content);    entry->content   = NULL;
    free(entry->source);     entry->source    = NULL;
    free(entry->category);   entry->category  = NULL;
    free(entry->embedding);  entry->embedding = NULL;
}

void
kelp_memory_entry_array_free(kelp_memory_entry_t *entries, int count)
{
    if (!entries) return;
    for (int i = 0; i < count; i++) {
        kelp_memory_entry_free(&entries[i]);
    }
    free(entries);
}

/* ----------------------------------------------------------------------- */
/* Static helpers                                                           */
/* ----------------------------------------------------------------------- */

static int
memory_init_schema(kelp_memory_t *mem)
{
    char *errmsg = NULL;

    /* Main entries table. */
    const char *sql_entries =
        "CREATE TABLE IF NOT EXISTS entries ("
        "  id         INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  content    TEXT NOT NULL,"
        "  source     TEXT NOT NULL DEFAULT '',"
        "  category   TEXT NOT NULL DEFAULT '',"
        "  created_at INTEGER NOT NULL,"
        "  updated_at INTEGER NOT NULL"
        ");";

    int rc = sqlite3_exec(mem->db, sql_entries, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        KELP_ERROR("create entries table: %s", errmsg);
        sqlite3_free(errmsg);
        return -1;
    }

    /* Create index on category for filtered queries. */
    sqlite3_exec(mem->db,
                 "CREATE INDEX IF NOT EXISTS idx_entries_category "
                 "ON entries(category);",
                 NULL, NULL, NULL);

    /* Try to create FTS5 virtual table. */
    const char *sql_fts =
        "CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5("
        "  content, source, content=entries, content_rowid=id"
        ");";
    rc = sqlite3_exec(mem->db, sql_fts, NULL, NULL, &errmsg);
    if (rc == SQLITE_OK) {
        mem->has_fts5 = true;
        KELP_DEBUG("FTS5 virtual table ready");
    } else {
        mem->has_fts5 = false;
        KELP_WARN("FTS5 not available: %s", errmsg);
        sqlite3_free(errmsg);
    }

    /* Try to create vec_entries if sqlite-vec is loaded. */
    if (mem->has_vec) {
        const char *sql_vec =
            "CREATE VIRTUAL TABLE IF NOT EXISTS vec_entries USING vec0("
            "  id INTEGER PRIMARY KEY,"
            "  embedding float[1536]"
            ");";
        rc = sqlite3_exec(mem->db, sql_vec, NULL, NULL, &errmsg);
        if (rc != SQLITE_OK) {
            KELP_WARN("vec_entries creation failed: %s", errmsg);
            sqlite3_free(errmsg);
            mem->has_vec = false;
        } else {
            KELP_DEBUG("vec_entries virtual table ready");
        }
    }

    return 0;
}

static int
memory_try_load_vec(kelp_memory_t *mem)
{
#ifdef __APPLE__
    /*
     * macOS system sqlite3 omits sqlite3_load_extension().
     * sqlite-vec is a Linux deployment target; skip on macOS.
     */
    (void)mem;
    mem->has_vec = false;
    KELP_DEBUG("sqlite-vec not available on macOS; vector search disabled");
    return -1;
#else
    /* Enable loading extensions. */
    sqlite3_db_config(mem->db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 1, NULL);

    /*
     * Try to load the sqlite-vec shared library.
     * Search common paths.
     */
    static const char *vec_paths[] = {
        "vec0",
        "./vec0",
        "/usr/lib/sqlite3/vec0",
        "/usr/local/lib/sqlite3/vec0",
        "/usr/lib/x86_64-linux-gnu/sqlite3/vec0",
        "/usr/lib/aarch64-linux-gnu/sqlite3/vec0",
        NULL
    };

    char *errmsg = NULL;
    for (int i = 0; vec_paths[i]; i++) {
        int rc = sqlite3_load_extension(mem->db, vec_paths[i], NULL, &errmsg);
        if (rc == SQLITE_OK) {
            mem->has_vec = true;
            KELP_INFO("loaded sqlite-vec from %s", vec_paths[i]);
            return 0;
        }
        if (errmsg) {
            sqlite3_free(errmsg);
            errmsg = NULL;
        }
    }

    mem->has_vec = false;
    KELP_DEBUG("sqlite-vec not found; vector search disabled");
    return -1;
#endif
}

static int
memory_prepare_statements(kelp_memory_t *mem)
{
    int rc;

    rc = sqlite3_prepare_v2(mem->db,
            "INSERT INTO entries(content, source, category, created_at, updated_at) "
            "VALUES(?, ?, ?, ?, ?);",
            -1, &mem->stmt_insert, NULL);
    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_prepare_v2(mem->db,
            "UPDATE entries SET content = ?, updated_at = ? WHERE id = ?;",
            -1, &mem->stmt_update, NULL);
    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_prepare_v2(mem->db,
            "DELETE FROM entries WHERE id = ?;",
            -1, &mem->stmt_delete, NULL);
    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_prepare_v2(mem->db,
            "SELECT id, content, source, category, created_at, updated_at "
            "FROM entries WHERE id = ?;",
            -1, &mem->stmt_get, NULL);
    if (rc != SQLITE_OK) return -1;

    return 0;
}

static void
memory_finalize_statements(kelp_memory_t *mem)
{
    if (mem->stmt_insert)     { sqlite3_finalize(mem->stmt_insert);     mem->stmt_insert     = NULL; }
    if (mem->stmt_update)     { sqlite3_finalize(mem->stmt_update);     mem->stmt_update     = NULL; }
    if (mem->stmt_delete)     { sqlite3_finalize(mem->stmt_delete);     mem->stmt_delete     = NULL; }
    if (mem->stmt_get)        { sqlite3_finalize(mem->stmt_get);        mem->stmt_get        = NULL; }
    if (mem->stmt_fts_search) { sqlite3_finalize(mem->stmt_fts_search); mem->stmt_fts_search = NULL; }
}

static char *
memory_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s);
    char *dup = malloc(len + 1);
    if (dup) {
        memcpy(dup, s, len + 1);
    }
    return dup;
}

static int64_t
memory_now(void)
{
    return (int64_t)time(NULL);
}

static double
cosine_similarity(const float *a, const float *b, int dim)
{
    if (!a || !b || dim <= 0) return 0.0;

    double dot = 0.0, norm_a = 0.0, norm_b = 0.0;
    for (int i = 0; i < dim; i++) {
        dot    += (double)a[i] * (double)b[i];
        norm_a += (double)a[i] * (double)a[i];
        norm_b += (double)b[i] * (double)b[i];
    }

    double denom = sqrt(norm_a) * sqrt(norm_b);
    if (denom < 1e-12) return 0.0;
    return dot / denom;
}

/*
 * MMR (Maximal Marginal Relevance) reranking.
 *
 * Iteratively selects entries that maximise:
 *   MMR(d) = lambda * score(d) - (1 - lambda) * max_sim(d, selected)
 *
 * When embeddings are not available, we approximate inter-document
 * similarity using simple Jaccard overlap on whitespace-tokenised content.
 */
static double
jaccard_similarity(const char *a, const char *b)
{
    if (!a || !b) return 0.0;

    /*
     * Cheap approximation: count shared whitespace-delimited tokens.
     * For production use with large text this would need a hash set;
     * here we keep it simple for moderate result sets.
     */
    size_t len_a = strlen(a);
    size_t len_b = strlen(b);

    /* Trivial size guard. */
    if (len_a == 0 || len_b == 0) return 0.0;
    if (len_a > 4096) len_a = 4096;
    if (len_b > 4096) len_b = 4096;

    /* Count shared 4-character shingles (character n-grams). */
    int shingle_len = 4;
    if ((int)len_a < shingle_len || (int)len_b < shingle_len) {
        /* Too short for shingles; rough character overlap. */
        int shared = 0;
        for (size_t i = 0; i < len_a && i < len_b; i++) {
            if (a[i] == b[i]) shared++;
        }
        size_t max_len = len_a > len_b ? len_a : len_b;
        return (double)shared / (double)max_len;
    }

    int count_a = (int)len_a - shingle_len + 1;
    int count_b = (int)len_b - shingle_len + 1;
    int shared = 0;

    /* O(n*m) but n,m are capped at ~4096 so manageable. */
    for (int i = 0; i < count_a; i++) {
        for (int j = 0; j < count_b; j++) {
            if (memcmp(a + i, b + j, (size_t)shingle_len) == 0) {
                shared++;
                break;  /* count each shingle in a at most once */
            }
        }
    }

    int total = count_a + count_b - shared;
    if (total <= 0) return 0.0;
    return (double)shared / (double)total;
}

static void
mmr_rerank(kelp_memory_entry_t *entries, int count, int desired, float lambda)
{
    if (count <= desired || count <= 1) return;

    /* Track which entries have been selected. */
    bool *selected = calloc((size_t)count, sizeof(bool));
    int  *order    = calloc((size_t)desired, sizeof(int));
    if (!selected || !order) {
        free(selected);
        free(order);
        return;
    }

    /* Normalise scores to [0, 1]. */
    double max_score = 0.0;
    for (int i = 0; i < count; i++) {
        if (entries[i].score > max_score) max_score = entries[i].score;
    }
    if (max_score > 0.0) {
        for (int i = 0; i < count; i++) {
            entries[i].score /= max_score;
        }
    }

    /* Greedy MMR selection. */
    for (int sel = 0; sel < desired && sel < count; sel++) {
        int    best_idx   = -1;
        double best_mmr   = -1e30;

        for (int i = 0; i < count; i++) {
            if (selected[i]) continue;

            /* Find maximum similarity to any already-selected entry. */
            double max_sim = 0.0;
            for (int s = 0; s < sel; s++) {
                double sim;
                int idx_s = order[s];

                /* Use embeddings if available, otherwise Jaccard. */
                if (entries[i].embedding && entries[idx_s].embedding &&
                    entries[i].embedding_dim == entries[idx_s].embedding_dim) {
                    sim = cosine_similarity(entries[i].embedding,
                                            entries[idx_s].embedding,
                                            entries[i].embedding_dim);
                } else {
                    sim = jaccard_similarity(entries[i].content,
                                             entries[idx_s].content);
                }
                if (sim > max_sim) max_sim = sim;
            }

            double mmr_val = (double)lambda * entries[i].score
                           - (double)(1.0f - lambda) * max_sim;

            if (mmr_val > best_mmr) {
                best_mmr = mmr_val;
                best_idx = i;
            }
        }

        if (best_idx < 0) break;
        selected[best_idx] = true;
        order[sel] = best_idx;
    }

    /* Rearrange entries in MMR order. */
    kelp_memory_entry_t *tmp = calloc((size_t)desired, sizeof(*tmp));
    if (tmp) {
        for (int i = 0; i < desired; i++) {
            tmp[i] = entries[order[i]];
        }
        /* Mark non-selected entries for cleanup (done by caller). */
        for (int i = 0; i < count; i++) {
            if (!selected[i]) {
                /* Entry will be freed by the caller after we set n_candidates. */
                continue;
            }
        }
        /* Copy reordered entries back. */
        memcpy(entries, tmp, (size_t)desired * sizeof(*tmp));
        free(tmp);
    }

    free(selected);
    free(order);
}
