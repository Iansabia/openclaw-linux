/*
 * kelp-linux :: libkelp-core
 * crypto.c - Cryptographic utilities (OpenSSL EVP backend)
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/crypto.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ---- SHA-256 ------------------------------------------------------------ */

void kelp_sha256(const void *data, size_t len, uint8_t out[32])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        memset(out, 0, 32);
        return;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, out, NULL) != 1) {
        memset(out, 0, 32);
    }

    EVP_MD_CTX_free(ctx);
}

void kelp_sha256_hex(const void *data, size_t len, char out[65])
{
    uint8_t digest[32];
    kelp_sha256(data, len, digest);

    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2]     = hex[(digest[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    out[64] = '\0';
}

/* ---- HMAC-SHA256 -------------------------------------------------------- */

void kelp_hmac_sha256(const void *key, size_t klen,
                       const void *data, size_t dlen,
                       uint8_t out[32])
{
    /*
     * Use the EVP_MAC API (OpenSSL 3.x).
     * Falls back gracefully: if any step fails, zero the output.
     */
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        memset(out, 0, 32);
        return;
    }

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        EVP_MAC_free(mac);
        memset(out, 0, 32);
        return;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    size_t out_len = 32;
    if (EVP_MAC_init(ctx, key, klen, params) != 1 ||
        EVP_MAC_update(ctx, data, dlen) != 1 ||
        EVP_MAC_final(ctx, out, &out_len, 32) != 1) {
        memset(out, 0, 32);
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
}

/* ---- Random bytes ------------------------------------------------------- */

int kelp_random_bytes(void *buf, size_t len)
{
    if (!buf || len == 0)
        return 0;
    return (RAND_bytes((unsigned char *)buf, (int)len) == 1) ? 0 : -1;
}

/* ---- Base64 ------------------------------------------------------------- */

char *kelp_base64_encode(const void *data, size_t len)
{
    if (!data || len == 0) {
        char *empty = malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }

    /*
     * EVP_EncodeBlock produces standard base64 without line breaks.
     * Output length is 4*ceil(len/3) + 1 for NUL.
     */
    size_t out_len = 4 * ((len + 2) / 3) + 1;
    char *out = malloc(out_len);
    if (!out)
        return NULL;

    int n = EVP_EncodeBlock((unsigned char *)out,
                            (const unsigned char *)data, (int)len);
    out[n] = '\0';
    return out;
}

uint8_t *kelp_base64_decode(const char *b64, size_t *out_len)
{
    if (!b64 || !out_len)
        return NULL;

    size_t b64_len = strlen(b64);
    if (b64_len == 0) {
        *out_len = 0;
        uint8_t *empty = malloc(1);
        return empty;
    }

    /* Upper bound: every 4 base64 chars decode to 3 bytes. */
    size_t max_len = 3 * (b64_len / 4) + 3;
    uint8_t *out = malloc(max_len);
    if (!out)
        return NULL;

    int n = EVP_DecodeBlock(out, (const unsigned char *)b64, (int)b64_len);
    if (n < 0) {
        free(out);
        return NULL;
    }

    /* Adjust for padding characters. */
    if (b64_len >= 2 && b64[b64_len - 1] == '=') n--;
    if (b64_len >= 2 && b64[b64_len - 2] == '=') n--;

    *out_len = (size_t)n;
    return out;
}

/* ---- Timing-safe comparison --------------------------------------------- */

int kelp_timing_safe_cmp(const void *a, const void *b, size_t len)
{
    const volatile unsigned char *pa = (const volatile unsigned char *)a;
    const volatile unsigned char *pb = (const volatile unsigned char *)b;
    unsigned char diff = 0;

    for (size_t i = 0; i < len; i++)
        diff |= pa[i] ^ pb[i];

    return (int)diff;
}
