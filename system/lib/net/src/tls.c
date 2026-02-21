/*
 * kelp-linux :: libkelp-net
 * tls.c - TLS context management (OpenSSL backend)
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/tls.h>
#include <kelp/log.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* ---- Internal structure ------------------------------------------------- */

struct kelp_tls_ctx {
    SSL_CTX *ssl_ctx;
};

/* ---- Helpers ------------------------------------------------------------ */

static void log_openssl_errors(const char *context)
{
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        KELP_ERROR("%s: %s", context, buf);
    }
}

/**
 * Test whether a path is a directory (for CA loading).
 */
static int is_directory(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    return S_ISDIR(st.st_mode);
}

/* ---- Public API --------------------------------------------------------- */

kelp_tls_ctx_t *kelp_tls_ctx_new(void)
{
    kelp_tls_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        KELP_ERROR("TLS context allocation failed");
        return NULL;
    }

    ctx->ssl_ctx = SSL_CTX_new(TLS_method());
    if (!ctx->ssl_ctx) {
        log_openssl_errors("SSL_CTX_new");
        free(ctx);
        return NULL;
    }

    /*
     * Set sane defaults:
     * - Minimum TLS 1.2
     * - Enable peer verification
     * - Load default CA certificates
     */
    SSL_CTX_set_min_proto_version(ctx->ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, NULL);

    if (SSL_CTX_set_default_verify_paths(ctx->ssl_ctx) != 1) {
        log_openssl_errors("SSL_CTX_set_default_verify_paths");
        /* Non-fatal: custom CA can still be loaded via set_ca */
    }

    /*
     * Prefer server cipher order and disable compression to mitigate
     * CRIME-style attacks.
     */
    SSL_CTX_set_options(ctx->ssl_ctx,
                        SSL_OP_CIPHER_SERVER_PREFERENCE |
                        SSL_OP_NO_COMPRESSION);

    KELP_DEBUG("TLS context created (TLS >= 1.2, verify=on)");
    return ctx;
}

void kelp_tls_ctx_free(kelp_tls_ctx_t *ctx)
{
    if (!ctx)
        return;

    if (ctx->ssl_ctx)
        SSL_CTX_free(ctx->ssl_ctx);

    free(ctx);
    KELP_DEBUG("TLS context freed");
}

int kelp_tls_ctx_set_cert(kelp_tls_ctx_t *ctx,
                           const char *cert_path,
                           const char *key_path)
{
    if (!ctx || !ctx->ssl_ctx || !cert_path || !key_path) {
        KELP_ERROR("tls_ctx_set_cert: invalid arguments");
        return -1;
    }

    if (SSL_CTX_use_certificate_chain_file(ctx->ssl_ctx, cert_path) != 1) {
        log_openssl_errors("SSL_CTX_use_certificate_chain_file");
        KELP_ERROR("Failed to load certificate: %s", cert_path);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, key_path,
                                    SSL_FILETYPE_PEM) != 1) {
        log_openssl_errors("SSL_CTX_use_PrivateKey_file");
        KELP_ERROR("Failed to load private key: %s", key_path);
        return -1;
    }

    if (SSL_CTX_check_private_key(ctx->ssl_ctx) != 1) {
        log_openssl_errors("SSL_CTX_check_private_key");
        KELP_ERROR("Certificate/key mismatch");
        return -1;
    }

    KELP_INFO("TLS certificate loaded: %s", cert_path);
    return 0;
}

int kelp_tls_ctx_set_ca(kelp_tls_ctx_t *ctx, const char *ca_path)
{
    if (!ctx || !ctx->ssl_ctx || !ca_path) {
        KELP_ERROR("tls_ctx_set_ca: invalid arguments");
        return -1;
    }

    int rc;
    if (is_directory(ca_path)) {
        rc = SSL_CTX_load_verify_locations(ctx->ssl_ctx, NULL, ca_path);
    } else {
        rc = SSL_CTX_load_verify_locations(ctx->ssl_ctx, ca_path, NULL);
    }

    if (rc != 1) {
        log_openssl_errors("SSL_CTX_load_verify_locations");
        KELP_ERROR("Failed to load CA from: %s", ca_path);
        return -1;
    }

    KELP_INFO("TLS CA loaded: %s", ca_path);
    return 0;
}

void kelp_tls_ctx_set_verify(kelp_tls_ctx_t *ctx, bool verify)
{
    if (!ctx || !ctx->ssl_ctx)
        return;

    if (verify) {
        SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, NULL);
        KELP_DEBUG("TLS peer verification enabled");
    } else {
        SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_NONE, NULL);
        KELP_WARN("TLS peer verification DISABLED -- insecure!");
    }
}
