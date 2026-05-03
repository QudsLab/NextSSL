/* yescrypt_ops.c — hash_ops_t accumulator wrapper for yescrypt (Alexander Peslyak)
 *
 * RESTRICTION: Only valid for seed_hash_derive_ex() CTR seeding where total
 * input is small (<= 2040 bytes).  Must NOT be used with HMAC, HKDF, or
 * PBKDF2 — the construction is undefined and has no security proof.
 *
 * Context fits in HASH_OPS_CTX_MAX (2048):
 *   buf[2040] + len[8] = 2048 bytes exactly.
 *
 * Parameters: flags=0 (classic scrypt mode), N=4096, r=8, p=1, t=0, g=0.
 * standalone mode (shared=NULL); local arena is init/freed per call.
 */
#include "../interface/hash_registry.h"
#include "yescrypt.h"
#include "../../common/secure_zero.h"
#include <string.h>
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t buf[2040];
    size_t  len;
} yescrypt_ops_ctx_t;

/* Domain separator for NextSSL seed derivation — fixed, non-zero, non-secret. */
static const uint8_t s_yescrypt_ops_salt[8] = {
    'N','X','T','S','Y','S','C', 0
};

static const yescrypt_params_t s_yescrypt_ops_params = {
    .flags = 0,      /* classic scrypt — no YESCRYPT_RW */
    .N     = 4096,
    .r     = 8,
    .p     = 1,
    .t     = 0,
    .g     = 0,
    .NROM  = 0
};

static void yescrypt_ops_init(void *c) {
    yescrypt_ops_ctx_t *ctx = (yescrypt_ops_ctx_t *)c;
    ctx->len = 0;
}

static void yescrypt_ops_update(void *c, const uint8_t *d, size_t l) {
    yescrypt_ops_ctx_t *ctx = (yescrypt_ops_ctx_t *)c;
    size_t room = sizeof(ctx->buf) - ctx->len;
    if (l > room) l = room;
    memcpy(ctx->buf + ctx->len, d, l);
    ctx->len += l;
}

static void yescrypt_ops_final(void *c, uint8_t *out) {
    yescrypt_ops_ctx_t *ctx = (yescrypt_ops_ctx_t *)c;
    yescrypt_local_t local;
    yescrypt_init_local(&local);
    yescrypt_kdf(NULL, &local,
                 ctx->buf, ctx->len,
                 s_yescrypt_ops_salt, sizeof(s_yescrypt_ops_salt),
                 &s_yescrypt_ops_params,
                 out, 32);
    yescrypt_free_local(&local);
    secure_zero(ctx->buf, ctx->len);
    ctx->len = 0;
}

const hash_ops_t yescrypt_ops = {
    .name        = "yescrypt",
    .digest_size = 32,
    .block_size  = 128,
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED,
    .init        = yescrypt_ops_init,
    .update      = yescrypt_ops_update,
    .final       = yescrypt_ops_final,
    .wu_per_eval = 4096.0,
    .mu_per_eval = 0.5,   /* ~512 KiB scratch at N=4096, r=8 */
    .parallelism = 1
};
