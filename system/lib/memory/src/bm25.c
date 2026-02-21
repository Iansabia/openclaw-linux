/*
 * kelp-linux :: libkelp-memory
 * bm25.c - BM25 scoring fallback (when FTS5 is unavailable)
 *
 * Implements Okapi BM25 with parameters k1=1.2, b=0.75.
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/log.h>

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>

/* ----------------------------------------------------------------------- */
/* Constants                                                                */
/* ----------------------------------------------------------------------- */

#define BM25_K1   1.2
#define BM25_B    0.75

/* Maximum number of unique tokens we track per document / query. */
#define MAX_TOKENS  8192

/* ----------------------------------------------------------------------- */
/* Internal helpers                                                         */
/* ----------------------------------------------------------------------- */

/**
 * Simple whitespace tokeniser.
 *
 * Returns a malloc'd array of malloc'd lowercase token strings.
 * The caller must free each token and the array itself.
 * *count is set to the number of tokens.
 */
static char **
tokenize(const char *text, int *count)
{
    *count = 0;
    if (!text || !*text) return NULL;

    int cap = 64;
    char **tokens = malloc((size_t)cap * sizeof(char *));
    if (!tokens) return NULL;

    const char *p = text;
    while (*p) {
        /* Skip whitespace and punctuation. */
        while (*p && (isspace((unsigned char)*p) || ispunct((unsigned char)*p)))
            p++;
        if (!*p) break;

        /* Find end of token. */
        const char *start = p;
        while (*p && !isspace((unsigned char)*p) && !ispunct((unsigned char)*p))
            p++;

        size_t len = (size_t)(p - start);
        if (len == 0) continue;

        if (*count >= cap) {
            cap *= 2;
            char **tmp = realloc(tokens, (size_t)cap * sizeof(char *));
            if (!tmp) break;
            tokens = tmp;
        }

        char *tok = malloc(len + 1);
        if (!tok) break;

        for (size_t i = 0; i < len; i++) {
            tok[i] = (char)tolower((unsigned char)start[i]);
        }
        tok[len] = '\0';

        tokens[*count] = tok;
        (*count)++;

        if (*count >= MAX_TOKENS) break;
    }

    return tokens;
}

static void
free_tokens(char **tokens, int count)
{
    if (!tokens) return;
    for (int i = 0; i < count; i++) {
        free(tokens[i]);
    }
    free(tokens);
}

/**
 * Count occurrences of `token` in the token array.
 */
static int
count_token(char **tokens, int n, const char *token)
{
    int c = 0;
    for (int i = 0; i < n; i++) {
        if (strcmp(tokens[i], token) == 0) c++;
    }
    return c;
}

/**
 * Count how many documents contain the given token.
 */
static int
doc_freq(const char ***all_doc_tokens, const int *doc_token_counts,
         int n_docs, const char *token)
{
    int df = 0;
    for (int d = 0; d < n_docs; d++) {
        for (int t = 0; t < doc_token_counts[d]; t++) {
            if (strcmp(all_doc_tokens[d][t], token) == 0) {
                df++;
                break;
            }
        }
    }
    return df;
}

/* ----------------------------------------------------------------------- */
/* Public (library-internal) API                                            */
/* ----------------------------------------------------------------------- */

/**
 * Compute BM25 scores for a set of documents against a query.
 *
 * @param query       The query string.
 * @param documents   Array of document strings.
 * @param n_docs      Number of documents.
 * @param scores      Pre-allocated output array of n_docs doubles.
 * @return 0 on success, -1 on error.
 *
 * Note: This function is declared in this translation unit and is intended
 * to be called from memory.c when FTS5 is not available.
 */
int
kelp_bm25_score(const char *query, const char **documents, int n_docs,
                  double *scores)
{
    if (!query || !documents || n_docs <= 0 || !scores) return -1;

    /* Tokenise the query. */
    int q_count = 0;
    char **q_tokens = tokenize(query, &q_count);
    if (q_count == 0) {
        free_tokens(q_tokens, q_count);
        for (int i = 0; i < n_docs; i++) scores[i] = 0.0;
        return 0;
    }

    /* Tokenise all documents. */
    char ***all_doc_tokens  = calloc((size_t)n_docs, sizeof(char **));
    int    *doc_token_counts = calloc((size_t)n_docs, sizeof(int));
    if (!all_doc_tokens || !doc_token_counts) {
        free_tokens(q_tokens, q_count);
        free(all_doc_tokens);
        free(doc_token_counts);
        return -1;
    }

    double avg_dl = 0.0;
    for (int d = 0; d < n_docs; d++) {
        all_doc_tokens[d] = (char **)tokenize(documents[d],
                                               &doc_token_counts[d]);
        avg_dl += doc_token_counts[d];
    }
    avg_dl /= (double)n_docs;

    /* Score each document. */
    for (int d = 0; d < n_docs; d++) {
        double score = 0.0;
        int dl = doc_token_counts[d];

        for (int qi = 0; qi < q_count; qi++) {
            const char *qt = q_tokens[qi];

            /* Term frequency in this document. */
            int tf = count_token(all_doc_tokens[d], dl, qt);
            if (tf == 0) continue;

            /* Document frequency. */
            int df = doc_freq((const char ***)all_doc_tokens,
                              doc_token_counts, n_docs, qt);

            /* IDF (with smoothing to avoid log(0)). */
            double idf = log(((double)n_docs - (double)df + 0.5) /
                             ((double)df + 0.5) + 1.0);

            /* BM25 TF component. */
            double tf_norm = ((double)tf * (BM25_K1 + 1.0)) /
                             ((double)tf + BM25_K1 *
                              (1.0 - BM25_B + BM25_B * ((double)dl / avg_dl)));

            score += idf * tf_norm;
        }

        scores[d] = score;
    }

    /* Cleanup. */
    for (int d = 0; d < n_docs; d++) {
        free_tokens(all_doc_tokens[d], doc_token_counts[d]);
    }
    free(all_doc_tokens);
    free(doc_token_counts);
    free_tokens(q_tokens, q_count);

    return 0;
}

/**
 * Compute BM25 score for a single document against a query.
 * This is a convenience wrapper that creates a trivial corpus of one document.
 * The IDF computation is less meaningful with N=1, but it still provides
 * a useful relevance signal for ranking.
 *
 * @return The BM25 score, or 0.0 on error.
 */
double
kelp_bm25_score_single(const char *query, const char *document)
{
    double score = 0.0;
    const char *docs[1] = { document };
    kelp_bm25_score(query, docs, 1, &score);
    return score;
}
