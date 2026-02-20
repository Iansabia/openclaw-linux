/*
 * clawd-linux :: libclawd-memory
 * test_memory.c - Unit tests for the memory subsystem
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/memory.h>
#include <clawd/embeddings.h>
#include <clawd/watcher.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* ----------------------------------------------------------------------- */
/* BM25 fallback declarations (defined in bm25.c)                           */
/* ----------------------------------------------------------------------- */

extern int    clawd_bm25_score(const char *query, const char **documents,
                                int n_docs, double *scores);
extern double clawd_bm25_score_single(const char *query,
                                       const char *document);

/* ----------------------------------------------------------------------- */
/* Helpers                                                                  */
/* ----------------------------------------------------------------------- */

static int tests_run    = 0;
static int tests_passed = 0;

#define TEST_START(name)                                                      \
    do {                                                                      \
        tests_run++;                                                          \
        printf("  [%2d] %-50s ", tests_run, (name));                          \
        fflush(stdout);                                                       \
    } while (0)

#define TEST_PASS()                                                           \
    do {                                                                      \
        tests_passed++;                                                       \
        printf("PASS\n");                                                     \
    } while (0)

#define TEST_ASSERT(expr)                                                     \
    do {                                                                      \
        if (!(expr)) {                                                        \
            printf("FAIL\n");                                                 \
            fprintf(stderr, "    assertion failed: %s (%s:%d)\n",             \
                    #expr, __FILE__, __LINE__);                               \
            return;                                                           \
        }                                                                     \
    } while (0)

/* ----------------------------------------------------------------------- */
/* Test: open and close memory store                                        */
/* ----------------------------------------------------------------------- */

static void
test_open_close(void)
{
    TEST_START("open/close in-memory store");

    clawd_memory_t *mem = clawd_memory_open(":memory:");
    TEST_ASSERT(mem != NULL);

    clawd_memory_close(mem);
    TEST_PASS();
}

/* ----------------------------------------------------------------------- */
/* Test: add and retrieve entries                                           */
/* ----------------------------------------------------------------------- */

static void
test_add_get(void)
{
    TEST_START("add and get entries");

    clawd_memory_t *mem = clawd_memory_open(":memory:");
    TEST_ASSERT(mem != NULL);

    int64_t id1 = clawd_memory_add(mem,
        "The quick brown fox jumps over the lazy dog.",
        "/tmp/test.txt", "doc");
    TEST_ASSERT(id1 > 0);

    int64_t id2 = clawd_memory_add(mem,
        "Rust is a systems programming language.",
        "user", "note");
    TEST_ASSERT(id2 > 0);
    TEST_ASSERT(id2 != id1);

    /* Retrieve the first entry. */
    clawd_memory_entry_t entry;
    int rc = clawd_memory_get(mem, id1, &entry);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(entry.id == id1);
    TEST_ASSERT(strcmp(entry.content, "The quick brown fox jumps over the lazy dog.") == 0);
    TEST_ASSERT(strcmp(entry.source, "/tmp/test.txt") == 0);
    TEST_ASSERT(strcmp(entry.category, "doc") == 0);
    TEST_ASSERT(entry.created_at > 0);
    TEST_ASSERT(entry.updated_at > 0);
    clawd_memory_entry_free(&entry);

    /* Retrieve the second entry. */
    rc = clawd_memory_get(mem, id2, &entry);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(entry.id == id2);
    TEST_ASSERT(strcmp(entry.content, "Rust is a systems programming language.") == 0);
    TEST_ASSERT(strcmp(entry.source, "user") == 0);
    TEST_ASSERT(strcmp(entry.category, "note") == 0);
    clawd_memory_entry_free(&entry);

    /* Non-existent id should fail. */
    rc = clawd_memory_get(mem, 99999, &entry);
    TEST_ASSERT(rc == -1);

    clawd_memory_close(mem);
    TEST_PASS();
}

/* ----------------------------------------------------------------------- */
/* Test: update an entry                                                    */
/* ----------------------------------------------------------------------- */

static void
test_update(void)
{
    TEST_START("update entry content");

    clawd_memory_t *mem = clawd_memory_open(":memory:");
    TEST_ASSERT(mem != NULL);

    int64_t id = clawd_memory_add(mem, "original content", "user", "note");
    TEST_ASSERT(id > 0);

    int rc = clawd_memory_update(mem, id, "updated content");
    TEST_ASSERT(rc == 0);

    clawd_memory_entry_t entry;
    rc = clawd_memory_get(mem, id, &entry);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(strcmp(entry.content, "updated content") == 0);
    clawd_memory_entry_free(&entry);

    /* Update non-existent id should fail. */
    rc = clawd_memory_update(mem, 99999, "something");
    TEST_ASSERT(rc == -1);

    clawd_memory_close(mem);
    TEST_PASS();
}

/* ----------------------------------------------------------------------- */
/* Test: delete an entry                                                    */
/* ----------------------------------------------------------------------- */

static void
test_delete(void)
{
    TEST_START("delete entry");

    clawd_memory_t *mem = clawd_memory_open(":memory:");
    TEST_ASSERT(mem != NULL);

    int64_t id = clawd_memory_add(mem, "to be deleted", "user", "note");
    TEST_ASSERT(id > 0);

    int rc = clawd_memory_delete(mem, id);
    TEST_ASSERT(rc == 0);

    /* Should no longer be retrievable. */
    clawd_memory_entry_t entry;
    rc = clawd_memory_get(mem, id, &entry);
    TEST_ASSERT(rc == -1);

    /* Double delete should fail. */
    rc = clawd_memory_delete(mem, id);
    TEST_ASSERT(rc == -1);

    clawd_memory_close(mem);
    TEST_PASS();
}

/* ----------------------------------------------------------------------- */
/* Test: search with BM25 (via FTS5 or LIKE fallback)                       */
/* ----------------------------------------------------------------------- */

static void
test_search_bm25(void)
{
    TEST_START("search entries (BM25 / text)");

    clawd_memory_t *mem = clawd_memory_open(":memory:");
    TEST_ASSERT(mem != NULL);

    /* Add several entries with distinct content. */
    clawd_memory_add(mem,
        "Linux kernel memory management and virtual memory subsystem.",
        "/docs/linux.txt", "doc");
    clawd_memory_add(mem,
        "How to bake a chocolate cake with cocoa powder and eggs.",
        "/docs/recipe.txt", "doc");
    clawd_memory_add(mem,
        "The C programming language was created by Dennis Ritchie.",
        "/docs/history.txt", "doc");
    clawd_memory_add(mem,
        "Memory allocation in C uses malloc, calloc, and realloc.",
        "/docs/c_memory.txt", "code");
    clawd_memory_add(mem,
        "Virtual machines provide hardware abstraction for operating systems.",
        "/docs/vm.txt", "doc");

    /* Search for "memory" -- should find relevant entries. */
    clawd_search_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.query      = "memory";
    opts.limit      = 10;
    opts.use_bm25   = true;
    opts.bm25_weight = 1.0f;
    opts.mmr_lambda  = 1.0f;  /* pure relevance, no diversity penalty */

    clawd_memory_entry_t *results = NULL;
    int count = 0;
    int rc = clawd_memory_search(mem, &opts, &results, &count);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(count > 0);

    /* Verify that at least one result contains "memory" (case insensitive). */
    int found_memory = 0;
    for (int i = 0; i < count; i++) {
        if (results[i].content &&
            (strstr(results[i].content, "memory") ||
             strstr(results[i].content, "Memory"))) {
            found_memory = 1;
        }
    }
    TEST_ASSERT(found_memory == 1);

    clawd_memory_entry_array_free(results, count);

    /* Search with category filter. */
    memset(&opts, 0, sizeof(opts));
    opts.query      = "memory";
    opts.limit      = 10;
    opts.use_bm25   = true;
    opts.category   = "code";
    opts.bm25_weight = 1.0f;
    opts.mmr_lambda  = 1.0f;

    results = NULL;
    count   = 0;
    rc = clawd_memory_search(mem, &opts, &results, &count);
    TEST_ASSERT(rc == 0);
    /* Should only return entries with category "code". */
    for (int i = 0; i < count; i++) {
        TEST_ASSERT(strcmp(results[i].category, "code") == 0);
    }

    clawd_memory_entry_array_free(results, count);
    clawd_memory_close(mem);
    TEST_PASS();
}

/* ----------------------------------------------------------------------- */
/* Test: BM25 scoring fallback                                              */
/* ----------------------------------------------------------------------- */

static void
test_bm25_scoring(void)
{
    TEST_START("BM25 scoring (fallback implementation)");

    const char *docs[] = {
        "The quick brown fox jumps over the lazy dog.",
        "A fox is a small omnivorous mammal.",
        "Dogs are domesticated mammals and loyal companions.",
        "The weather today is sunny and warm."
    };

    double scores[4];
    int rc = clawd_bm25_score("fox", docs, 4, scores);
    TEST_ASSERT(rc == 0);

    /* "fox" should score highest for the first two documents. */
    TEST_ASSERT(scores[0] > scores[3]);
    TEST_ASSERT(scores[1] > scores[3]);

    /* Document with no relevant terms should score ~0. */
    TEST_ASSERT(scores[3] < 0.01);

    /* Single-document convenience function. */
    double s = clawd_bm25_score_single("fox", docs[0]);
    TEST_ASSERT(s > 0.0);

    TEST_PASS();
}

/* ----------------------------------------------------------------------- */
/* Test: embeddings dimension                                               */
/* ----------------------------------------------------------------------- */

static void
test_embed_dimension(void)
{
    TEST_START("embedding provider dimensions");

    int d = clawd_embed_dimension(CLAWD_EMBED_OPENAI);
    TEST_ASSERT(d == 1536);

    d = clawd_embed_dimension(CLAWD_EMBED_LOCAL);
    TEST_ASSERT(d == 384);

    TEST_PASS();
}

/* ----------------------------------------------------------------------- */
/* Test: embeddings context lifecycle                                       */
/* ----------------------------------------------------------------------- */

static void
test_embed_ctx_lifecycle(void)
{
    TEST_START("embedding context new/free");

    /* With a dummy key (no actual API calls). */
    clawd_embed_ctx_t *ctx = clawd_embed_ctx_new(CLAWD_EMBED_OPENAI,
                                                  "sk-test-dummy-key");
    TEST_ASSERT(ctx != NULL);
    clawd_embed_ctx_free(ctx);

    /* Local provider with NULL key. */
    ctx = clawd_embed_ctx_new(CLAWD_EMBED_LOCAL, NULL);
    TEST_ASSERT(ctx != NULL);
    clawd_embed_ctx_free(ctx);

    /* Free NULL should be safe. */
    clawd_embed_ctx_free(NULL);

    TEST_PASS();
}

/* ----------------------------------------------------------------------- */
/* Test: watcher init/free                                                  */
/* ----------------------------------------------------------------------- */

static void
test_watcher_lifecycle(void)
{
    TEST_START("watcher new/free");

    clawd_watcher_t *w = clawd_watcher_new();
    TEST_ASSERT(w != NULL);

    int fd = clawd_watcher_fd(w);
    TEST_ASSERT(fd >= 0);

    clawd_watcher_free(w);

    /* Free NULL should be safe. */
    clawd_watcher_free(NULL);

    TEST_PASS();
}

/* ----------------------------------------------------------------------- */
/* Test: watcher add/remove                                                 */
/* ----------------------------------------------------------------------- */

static void
test_watcher_add_remove(void)
{
    TEST_START("watcher add/remove path");

    clawd_watcher_t *w = clawd_watcher_new();
    TEST_ASSERT(w != NULL);

    /* Watch /tmp (should exist on all POSIX systems). */
    int rc = clawd_watcher_add(w, "/tmp", CLAWD_WATCH_ALL, false);
    TEST_ASSERT(rc == 0);

    /* Remove it. */
    rc = clawd_watcher_remove(w, "/tmp");
    TEST_ASSERT(rc == 0);

    /* Removing again should fail. */
    rc = clawd_watcher_remove(w, "/tmp");
    TEST_ASSERT(rc == -1);

    clawd_watcher_free(w);
    TEST_PASS();
}

/* ----------------------------------------------------------------------- */
/* Test: entry free safety                                                  */
/* ----------------------------------------------------------------------- */

static void
test_entry_free_safety(void)
{
    TEST_START("entry free with NULL fields");

    clawd_memory_entry_t entry;
    memset(&entry, 0, sizeof(entry));

    /* Should not crash. */
    clawd_memory_entry_free(&entry);
    clawd_memory_entry_free(NULL);
    clawd_memory_entry_array_free(NULL, 0);

    TEST_PASS();
}

/* ----------------------------------------------------------------------- */
/* Test: multiple adds and search ordering                                  */
/* ----------------------------------------------------------------------- */

static void
test_search_ordering(void)
{
    TEST_START("search result ordering");

    clawd_memory_t *mem = clawd_memory_open(":memory:");
    TEST_ASSERT(mem != NULL);

    /* Add entries where one is clearly more relevant. */
    clawd_memory_add(mem,
        "PostgreSQL is a relational database management system.",
        "user", "note");
    clawd_memory_add(mem,
        "SQLite is a lightweight embedded database engine. "
        "SQLite stores data in a single file. "
        "SQLite is perfect for embedded database applications.",
        "user", "note");
    clawd_memory_add(mem,
        "Python is a general-purpose programming language.",
        "user", "note");

    clawd_search_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.query      = "SQLite database";
    opts.limit      = 10;
    opts.use_bm25   = true;
    opts.bm25_weight = 1.0f;
    opts.mmr_lambda  = 1.0f;

    clawd_memory_entry_t *results = NULL;
    int count = 0;
    int rc = clawd_memory_search(mem, &opts, &results, &count);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(count > 0);

    /* The first result should mention "SQLite". */
    TEST_ASSERT(results[0].content != NULL);
    TEST_ASSERT(strstr(results[0].content, "SQLite") != NULL);

    clawd_memory_entry_array_free(results, count);
    clawd_memory_close(mem);
    TEST_PASS();
}

/* ----------------------------------------------------------------------- */
/* Main                                                                     */
/* ----------------------------------------------------------------------- */

int
main(void)
{
    printf("libclawd-memory :: test suite\n");
    printf("====================================\n\n");

    test_open_close();
    test_add_get();
    test_update();
    test_delete();
    test_search_bm25();
    test_bm25_scoring();
    test_embed_dimension();
    test_embed_ctx_lifecycle();
    test_watcher_lifecycle();
    test_watcher_add_remove();
    test_entry_free_safety();
    test_search_ordering();

    printf("\n====================================\n");
    printf("Results: %d / %d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
