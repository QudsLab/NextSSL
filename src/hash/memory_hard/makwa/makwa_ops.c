/* makwa_ops.c — hash_ops_t stub for Makwa (Plan 205)
 *
 * Makwa source (Thomas Pornin, MIT) is not yet available in this tree.
 * This file provides the hash_ops_t extern declaration only when
 * NEXTSSL_HAS_MAKWA is defined.
 *
 * Makwa is unusual in that it is based on modular squaring (2048-bit or
 * 4096-bit modulus) rather than symmetric primitives. The work factor is
 * the number of squarings (default: 4096).
 *
 * When NEXTSSL_HAS_MAKWA is defined and makwa.c is present, this stub
 * becomes a full accumulator wrapper following the same pattern as the
 * other memory-hard wrappers.
 */
#include "../../interface/hash_registry.h"

#include "makwa.h"
#include "../../../common/secure_zero.h"
#include <string.h>
#include <stdint.h>

/* Context layout: buf[2016] + salt[16] + salt_len[1] + _pad[7] + len[8] = 2048
 * = HASH_OPS_CTX_MAX exactly (Plan 40003). */
typedef struct {
    uint8_t buf[2016];   /* accumulator                                     */
    uint8_t salt[16];    /* optional caller-configured salt (Plan 40003)     */
    uint8_t salt_len;    /* 0 = use domain separator; >0 = use salt[]        */
    uint8_t _pad[7];     /* alignment — keeps len at offset 2040             */
    size_t  len;         /* bytes in buf                                     */
} makwa_ops_ctx_t;

static void makwa_ops_init(void *c) {
    makwa_ops_ctx_t *ctx = (makwa_ops_ctx_t *)c;
    ctx->len = 0;
    /* salt field intentionally NOT reset — survives across init calls */
}

/* makwa_ops_set_salt — configure override salt before init/update/final (Plan 40003)
 * Pass NULL or salt_len=0 to revert to the domain-separator default. */
void makwa_ops_set_salt(void *ctx_raw, const uint8_t *salt, size_t salt_len)
{
    makwa_ops_ctx_t *ctx = (makwa_ops_ctx_t *)ctx_raw;
    if (!ctx || !salt || salt_len == 0) {
        if (ctx) ctx->salt_len = 0;
        return;
    }
    size_t copy = salt_len > sizeof(ctx->salt) ? sizeof(ctx->salt) : salt_len;
    memcpy(ctx->salt, salt, copy);
    ctx->salt_len = (uint8_t)copy;
}

static void makwa_ops_update(void *c, const uint8_t *d, size_t l) {
    makwa_ops_ctx_t *ctx = (makwa_ops_ctx_t *)c;
    size_t room = sizeof(ctx->buf) - ctx->len;
    if (l > room) l = room;
    memcpy(ctx->buf + ctx->len, d, l);
    ctx->len += l;
}

#define MAKWA_OPS_WORK_FACTOR  4096   /* squarings: 2^12 per spec default */

static void makwa_ops_final(void *c, uint8_t *out) {
    makwa_ops_ctx_t *ctx = (makwa_ops_ctx_t *)c;
    /* Domain separator — default when no salt configured (Plan 40003). */
    static const uint8_t s_default[8] = {'N','X','T','S','M','K','W', 0};
    const uint8_t *s   = ctx->salt_len ? ctx->salt : s_default;
    size_t         sln = ctx->salt_len ? ctx->salt_len : sizeof(s_default);
    makwa_hash(ctx->buf, ctx->len, s, sln, MAKWA_OPS_WORK_FACTOR, out, 32);
    secure_zero(ctx->buf, ctx->len);
    ctx->len = 0;
}

const hash_ops_t makwa_ops = {
    .name        = "makwa",
    .digest_size = 32,
    .block_size  = 64,
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED,
    .init        = makwa_ops_init,
    .update      = makwa_ops_update,
    .final       = makwa_ops_final,
    .wu_per_eval = 8192.0,   /* 2*work_factor (mod squarings are expensive) */
    .mu_per_eval = 0.5,      /* ~2048-bit modulus operations, small scratch */
    .parallelism = 1
};
