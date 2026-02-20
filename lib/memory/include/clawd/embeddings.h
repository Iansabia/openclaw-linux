/*
 * clawd-linux :: libclawd-memory
 * embeddings.h - Embedding API client
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_EMBEDDINGS_H
#define CLAWD_EMBEDDINGS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Supported embedding providers. */
typedef enum {
    CLAWD_EMBED_OPENAI,    /* text-embedding-3-small (1536-dim) */
    CLAWD_EMBED_LOCAL      /* local model via HTTP */
} clawd_embed_provider_t;

/** Opaque embedding context. */
typedef struct clawd_embed_ctx clawd_embed_ctx_t;

/**
 * Create a new embedding context.
 *
 * @param provider  The embedding provider to use.
 * @param api_key   API key (required for OPENAI, may be NULL for LOCAL).
 * @return Context handle on success, NULL on failure.
 */
clawd_embed_ctx_t *clawd_embed_ctx_new(clawd_embed_provider_t provider,
                                        const char *api_key);

/**
 * Free an embedding context.
 */
void clawd_embed_ctx_free(clawd_embed_ctx_t *ctx);

/**
 * Compute the embedding for a single text.
 *
 * @param ctx        Embedding context.
 * @param text       Input text.
 * @param embedding  On success, set to a malloc'd float array.
 * @param dim        On success, set to the embedding dimension.
 * @return 0 on success, -1 on error.
 *
 * Caller must free(*embedding).
 */
int clawd_embed_text(clawd_embed_ctx_t *ctx, const char *text,
                      float **embedding, int *dim);

/**
 * Compute embeddings for a batch of texts in a single request.
 *
 * @param ctx         Embedding context.
 * @param texts       Array of input texts.
 * @param count       Number of texts.
 * @param embeddings  On success, set to a malloc'd flat array of
 *                    (count * dim) floats.
 * @param dim         On success, set to the embedding dimension.
 * @return 0 on success, -1 on error.
 *
 * Caller must free(*embeddings).
 */
int clawd_embed_batch(clawd_embed_ctx_t *ctx, const char **texts, int count,
                       float **embeddings, int *dim);

/**
 * Return the embedding dimension for a provider.
 *
 * @return Dimension (e.g. 1536 for OpenAI), or -1 if unknown.
 */
int clawd_embed_dimension(clawd_embed_provider_t provider);

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_EMBEDDINGS_H */
