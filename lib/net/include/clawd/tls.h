/*
 * clawd-linux :: libclawd-net
 * tls.h - TLS context management (OpenSSL backend)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_TLS_H
#define CLAWD_TLS_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque TLS context handle. */
typedef struct clawd_tls_ctx clawd_tls_ctx_t;

/** Create a new TLS context with sane defaults.  Returns NULL on failure. */
clawd_tls_ctx_t *clawd_tls_ctx_new(void);

/** Free a TLS context and all associated resources. */
void clawd_tls_ctx_free(clawd_tls_ctx_t *ctx);

/**
 * Load a client certificate and private key.
 * Returns 0 on success, -1 on error.
 */
int clawd_tls_ctx_set_cert(clawd_tls_ctx_t *ctx,
                           const char *cert_path,
                           const char *key_path);

/**
 * Load trusted CA certificates from a file or directory.
 * Returns 0 on success, -1 on error.
 */
int clawd_tls_ctx_set_ca(clawd_tls_ctx_t *ctx, const char *ca_path);

/**
 * Enable or disable peer certificate verification.
 * Verification is enabled by default.
 */
void clawd_tls_ctx_set_verify(clawd_tls_ctx_t *ctx, bool verify);

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_TLS_H */
