/* catena_ops.c — hash_ops_t accumulator wrapper for Catena (Christian Forler et al.)
 *
 * RESTRICTION: Only valid for seed_hash_derive_ex() CTR seeding where total
 * input is small (<= 2040 bytes).  Must NOT be used with HMAC, HKDF, or
 * PBKDF2 — the construction is undefined and has no security proof.
 *
 * Context fits in HASH_OPS_CTX_MAX (2048):
 *   buf[2040] + len[8] = 2048 bytes exactly.
 *
 * Parameters: lambda=2, min_garlic=8, garlic=8, hashlen=32.
 *   garlic=8 → 2^8 * H_LEN (64) = 16 KiB memory.
 *   Empty salt and associated data — key material is accumulated in buf.
 *
 * Windows portability: catena.h includes a portable endian shim instead of
 * the Linux-only <endian.h>; see catena.h for the detection logic.
 */
#include "../../interface/hash_registry.h"
#include "catena.h"
#include "../../../common/secure_zero.h"
#include <string.h>
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t buf[2040];
    size_t  len;
} catena_ops_ctx_t;

#define CATENA_OPS_LAMBDA     2
#define CATENA_OPS_MIN_GARLIC 8
#define CATENA_OPS_GARLIC     8
#define CATENA_OPS_HASHLEN    32

static void catena_ops_init(void *c) {
    catena_ops_ctx_t *ctx = (catena_ops_ctx_t *)c;
    ctx->len = 0;
}

static void catena_ops_update(void *c, const uint8_t *d, size_t l) {
    catena_ops_ctx_t *ctx = (catena_ops_ctx_t *)c;
    size_t room = sizeof(ctx->buf) - ctx->len;
    if (l > room) l = room;
    memcpy(ctx->buf + ctx->len, d, l);
    ctx->len += l;
}

static void catena_ops_final(void *c, uint8_t *out) {
    catena_ops_ctx_t *ctx = (catena_ops_ctx_t *)c;
    /* Catena saltlen is uint8_t (max 255) — empty salt for hash_ops use */
    Catena(ctx->buf,  (uint32_t)ctx->len,
           NULL,      0,   /* salt */
           NULL,      0,   /* associated data */
           CATENA_OPS_LAMBDA,
           CATENA_OPS_MIN_GARLIC,
           CATENA_OPS_GARLIC,
           CATENA_OPS_HASHLEN,
           out);
    secure_zero(ctx->buf, ctx->len);
    ctx->len = 0;
}

const hash_ops_t catena_ops = {
    .name        = "catena",
    .digest_size = 32,
    .block_size  = 64,
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED,
    .init        = catena_ops_init,
    .update      = catena_ops_update,
    .final       = catena_ops_final,
    .wu_per_eval = 256.0,
    .mu_per_eval = 0.016,  /* ~16 KiB at garlic=8 */
    .parallelism = 1
};
