/* scrypt_ops.c — hash_ops_t accumulator wrapper for Colin Percival's scrypt
 *
 * RESTRICTION: Only valid for seed_hash_derive_ex() CTR seeding where total
 * input is small (<= 2040 bytes).  Must NOT be used with HMAC, HKDF, or
 * PBKDF2 — the construction is undefined and has no security proof.
 *
 * Context fits in HASH_OPS_CTX_MAX (2048):
 *   buf[2040] + len[8] = 2048 bytes exactly.
 *
 * Parameters: N=4096, r=8, p=1 — reduced from default for hash_ops use.
 * The fixed salt is all-zeros (the password/key material is in buf).
 */
#include "../interface/hash_registry.h"
#include "crypto_scrypt.h"
#include "../../common/secure_zero.h"
#include <string.h>
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t buf[2040];
    size_t  len;
} scrypt_ops_ctx_t;

/* Domain separator for NextSSL seed derivation — fixed, non-zero, non-secret. */
static const uint8_t s_scrypt_ops_salt[8] = {
    'N','X','T','S','C','R','P', 0
};

#define SCRYPT_OPS_N  4096
#define SCRYPT_OPS_R  8
#define SCRYPT_OPS_P  1

static void scrypt_ops_init(void *c) {
    scrypt_ops_ctx_t *ctx = (scrypt_ops_ctx_t *)c;
    ctx->len = 0;
}

static void scrypt_ops_update(void *c, const uint8_t *d, size_t l) {
    scrypt_ops_ctx_t *ctx = (scrypt_ops_ctx_t *)c;
    size_t room = sizeof(ctx->buf) - ctx->len;
    if (l > room) l = room;
    memcpy(ctx->buf + ctx->len, d, l);
    ctx->len += l;
}

static void scrypt_ops_final(void *c, uint8_t *out) {
    scrypt_ops_ctx_t *ctx = (scrypt_ops_ctx_t *)c;
    crypto_scrypt(ctx->buf, ctx->len,
                  s_scrypt_ops_salt, sizeof(s_scrypt_ops_salt),
                  SCRYPT_OPS_N, SCRYPT_OPS_R, SCRYPT_OPS_P,
                  out, 32);
    secure_zero(ctx->buf, ctx->len);
    ctx->len = 0;
}

const hash_ops_t scrypt_ops = {
    .name        = "scrypt",
    .digest_size = 32,
    .block_size  = 128,
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED,
    .init        = scrypt_ops_init,
    .update      = scrypt_ops_update,
    .final       = scrypt_ops_final,
    .wu_per_eval = 4096.0,
    .mu_per_eval = 0.5,   /* ~512 KiB scratch at N=4096, r=8 */
    .parallelism = 1
};
