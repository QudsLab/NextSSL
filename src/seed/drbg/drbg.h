/* drbg.h — Hash-based DRBG shim for deterministic key generation
 *
 * Provides a simple SHA-256 counter-mode DRBG used by curve448_det.c
 * and similar deterministic key generation helpers.
 *
 * NOT a NIST SP 800-90A compliant DRBG — this is a minimal deterministic
 * PRF for seed → key-material expansion within the library internals.
 * External callers should use nextssl_seed_derive() via the root API.
 */
#ifndef SEED_DRBG_H
#define SEED_DRBG_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Pull in SHA-256 from the hash module. */
#include "sha256.h"

#define DRBG_SEED_MAX 64

typedef struct {
    uint8_t  seed[DRBG_SEED_MAX];
    size_t   seed_len;
    uint32_t counter;
    /* leftover block */
    uint8_t  buf[32];
    size_t   buf_off;
} DRBG_CTX;

/* drbg_init — seed the DRBG */
static inline void drbg_init(DRBG_CTX *ctx, const uint8_t *seed, size_t seed_len)
{
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
    if (seed && seed_len > 0) {
        size_t copy = seed_len < DRBG_SEED_MAX ? seed_len : DRBG_SEED_MAX;
        memcpy(ctx->seed, seed, copy);
        ctx->seed_len = copy;
    }
}

/* drbg_generate — fill out[0..len-1] with deterministic pseudorandom bytes */
static inline int drbg_generate(DRBG_CTX *ctx, uint8_t *out, size_t len)
{
    if (!ctx || !out) return -1;

    size_t written = 0;

    /* Drain leftover from previous block */
    while (ctx->buf_off < 32 && written < len) {
        out[written++] = ctx->buf[ctx->buf_off++];
    }

    /* Generate full SHA-256 blocks: H(seed || counter) */
    while (written < len) {
        SHA256_CTX hctx;
        uint8_t block[32];
        uint8_t ctr_bytes[4];
        ctr_bytes[0] = (ctx->counter >> 24) & 0xFF;
        ctr_bytes[1] = (ctx->counter >> 16) & 0xFF;
        ctr_bytes[2] = (ctx->counter >>  8) & 0xFF;
        ctr_bytes[3] = (ctx->counter      ) & 0xFF;
        ctx->counter++;

        sha256_init(&hctx);
        sha256_update(&hctx, ctx->seed, ctx->seed_len);
        sha256_update(&hctx, ctr_bytes, 4);
        sha256_final(&hctx, block);

        size_t take = len - written;
        if (take >= 32) {
            memcpy(out + written, block, 32);
            written += 32;
        } else {
            memcpy(out + written, block, take);
            /* Save leftover */
            memcpy(ctx->buf, block + take, 32 - take);
            ctx->buf_off = 0;
            /* adjust: buf now holds the tail, buf_off should point after what we took */
            ctx->buf_off = 0;
            memmove(ctx->buf, block + take, 32 - take);
            ctx->buf_off = 0;
            written += take;
        }
    }
    return 0;
}

/* drbg_wipe — zero-clear the DRBG context */
static inline void drbg_wipe(DRBG_CTX *ctx)
{
    if (ctx) memset(ctx, 0, sizeof(*ctx));
}

/* drbg_reseed — re-key the DRBG with new seed material (alias for drbg_init) */
static inline void drbg_reseed(DRBG_CTX *ctx, const uint8_t *seed, size_t seed_len)
{
    drbg_init(ctx, seed, seed_len);
}

#endif /* SEED_DRBG_H */
