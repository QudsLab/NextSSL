/* lyra2_ops.c — hash_ops_t accumulator wrapper for Lyra2 (Simplicio et al.)
 *
 * RESTRICTION: Only valid for seed_hash_derive_ex() CTR seeding where total
 * input is small (<= 2040 bytes).  Must NOT be used with HMAC, HKDF, or
 * PBKDF2 — the construction is undefined and has no security proof.
 *
 * Context fits in HASH_OPS_CTX_MAX (2048):
 *   buf[2040] + len[8] = 2048 bytes exactly.
 *
 * Parameters: timeCost=1, nRows=8, nCols=256.
 *   Memory: nRows * nCols * BLOCK_LEN_BLAKE2_SAFE_BYTES ≈ 8 * 256 * 96 = 192 KiB.
 *
 * Lyra2 uses OpenMP for parallel execution; nPARALLEL is a compile-time
 * constant (default=2 in the source but overridable). For hash_ops the
 * implementation is called single-threaded when OpenMP is not enabled.
 */
#include "../../interface/hash_registry.h"
#include "Lyra2.h"
#include "../../../common/secure_zero.h"
#include <string.h>
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t buf[2040];
    size_t  len;
} lyra2_ops_ctx_t;

/* Domain separator for NextSSL seed derivation — fixed, non-zero, non-secret. */
static const uint8_t s_lyra2_ops_salt[8] = {
    'N','X','T','S','L','Y','2', 0
};

#define LYRA2_OPS_TIME_COST  1
#define LYRA2_OPS_NROWS      8
#define LYRA2_OPS_NCOLS      256

static void lyra2_ops_init(void *c) {
    lyra2_ops_ctx_t *ctx = (lyra2_ops_ctx_t *)c;
    ctx->len = 0;
}

static void lyra2_ops_update(void *c, const uint8_t *d, size_t l) {
    lyra2_ops_ctx_t *ctx = (lyra2_ops_ctx_t *)c;
    size_t room = sizeof(ctx->buf) - ctx->len;
    if (l > room) l = room;
    memcpy(ctx->buf + ctx->len, d, l);
    ctx->len += l;
}

static void lyra2_ops_final(void *c, uint8_t *out) {
    lyra2_ops_ctx_t *ctx = (lyra2_ops_ctx_t *)c;
    LYRA2(out, 32,
          ctx->buf, (unsigned int)ctx->len,
          s_lyra2_ops_salt, (unsigned int)sizeof(s_lyra2_ops_salt),
          LYRA2_OPS_TIME_COST,
          LYRA2_OPS_NROWS,
          LYRA2_OPS_NCOLS);
    secure_zero(ctx->buf, ctx->len);
    ctx->len = 0;
}

const hash_ops_t lyra2_ops = {
    .name        = "lyra2",
    .digest_size = 32,
    .block_size  = 64,
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED,
    .init        = lyra2_ops_init,
    .update      = lyra2_ops_update,
    .final       = lyra2_ops_final,
    .wu_per_eval = 2048.0,
    .mu_per_eval = 0.19,   /* ~192 KiB at nRows=8, nCols=256 */
    .parallelism = 1
};
