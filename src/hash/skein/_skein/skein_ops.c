/* skein_ops.c — hash_ops_t wrappers for Skein-256, Skein-512, Skein-1024
 *
 * Source: wernerd/Skein3Fish (Werner Dittmann), MIT licence.
 * Core algorithm by Doug Whiting — released to the public domain.
 *
 * Build note: this file must be compiled with -I src/hash/skein (or equivalent)
 * so that angle-bracket includes inside skeinApi.h and skein.h resolve.
 *
 * Context: SkeinCtx_t is ~424 bytes — well within HASH_OPS_CTX_MAX (2048).
 */
#include "../interface/hash_registry.h"
#include "skeinApi.h"

/* =========================================================================
 * Skein-256 — 256-bit state, 256-bit output
 * ========================================================================= */
static void skein256_ops_init(void *c) {
    SkeinCtx_t *ctx = (SkeinCtx_t *)c;
    skeinCtxPrepare(ctx, Skein256);
    skeinInit(ctx, 256);
}

static void skein256_ops_update(void *c, const uint8_t *d, size_t l) {
    skeinUpdate((SkeinCtx_t *)c, d, l);
}

static void skein256_ops_final(void *c, uint8_t *out) {
    skeinFinal((SkeinCtx_t *)c, out);
}

const hash_ops_t skein256_ops = {
    .name        = "skein256",
    .digest_size = 32,
    .block_size  = 32,        /* Skein-256 processes 256-bit (32-byte) blocks */
    .usage_flags = HASH_USAGE_ALL,
    .init        = skein256_ops_init,
    .update      = skein256_ops_update,
    .final       = skein256_ops_final,
    .wu_per_eval = 1.2,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * Skein-512 — 512-bit state, 256-bit output
 * ========================================================================= */
static void skein512_ops_init(void *c) {
    SkeinCtx_t *ctx = (SkeinCtx_t *)c;
    skeinCtxPrepare(ctx, Skein512);
    skeinInit(ctx, 256);
}

static void skein512_ops_update(void *c, const uint8_t *d, size_t l) {
    skeinUpdate((SkeinCtx_t *)c, d, l);
}

static void skein512_ops_final(void *c, uint8_t *out) {
    skeinFinal((SkeinCtx_t *)c, out);
}

const hash_ops_t skein512_ops = {
    .name        = "skein512",
    .digest_size = 32,
    .block_size  = 64,        /* Skein-512 processes 512-bit (64-byte) blocks */
    .usage_flags = HASH_USAGE_ALL,
    .init        = skein512_ops_init,
    .update      = skein512_ops_update,
    .final       = skein512_ops_final,
    .wu_per_eval = 1.5,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * Skein-1024 — 1024-bit state, 512-bit output
 * ========================================================================= */
static void skein1024_ops_init(void *c) {
    SkeinCtx_t *ctx = (SkeinCtx_t *)c;
    skeinCtxPrepare(ctx, Skein1024);
    skeinInit(ctx, 512);
}

static void skein1024_ops_update(void *c, const uint8_t *d, size_t l) {
    skeinUpdate((SkeinCtx_t *)c, d, l);
}

static void skein1024_ops_final(void *c, uint8_t *out) {
    skeinFinal((SkeinCtx_t *)c, out);
}

const hash_ops_t skein1024_ops = {
    .name        = "skein1024",
    .digest_size = 64,
    .block_size  = 128,       /* Skein-1024 processes 1024-bit (128-byte) blocks */
    .usage_flags = HASH_USAGE_ALL,
    .init        = skein1024_ops_init,
    .update      = skein1024_ops_update,
    .final       = skein1024_ops_final,
    .wu_per_eval = 2.5,
    .mu_per_eval = 0.0,
    .parallelism = 1
};
