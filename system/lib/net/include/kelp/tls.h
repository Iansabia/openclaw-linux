/*
 * kelp-linux :: libkelp-net
 * tls.h - TLS context management (OpenSSL backend)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KELP_TLS_H
#define KELP_TLS_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque TLS context handle. */
typedef struct kelp_tls_ctx kelp_tls_ctx_t;

/** Create a new TLS context with sane defaults.  Returns NULL on failure. */
kelp_tls_ctx_t *kelp_tls_ctx_new(void);

/** Free a TLS context and all associated resources. */
void kelp_tls_ctx_free(kelp_tls_ctx_t *ctx);

/**
 * Load a client certificate and private key.
 * Returns 0 on success, -1 on error.
 */
int kelp_tls_ctx_set_cert(kelp_tls_ctx_t *ctx,
                           const char *cert_path,
                           const char *key_path);

/**
 * Load trusted CA certificates from a file or directory.
 * Returns 0 on success, -1 on error.
 */
int kelp_tls_ctx_set_ca(kelp_tls_ctx_t *ctx, const char *ca_path);

/**
 * Enable or disable peer certificate verification.
 * Verification is enabled by default.
 */
void kelp_tls_ctx_set_verify(kelp_tls_ctx_t *ctx, bool verify);

#ifdef __cplusplus
}
#endif

#endif /* KELP_TLS_H */
