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

#ifdef NEXTSSL_HAS_MAKWA
#include "makwa.h"
#include "../../../common/secure_zero.h"
#include <string.h>
#include <stdint.h>

typedef struct {
    uint8_t buf[2040];
    size_t  len;
} makwa_ops_ctx_t;

static void makwa_ops_init(void *c) {
    makwa_ops_ctx_t *ctx = (makwa_ops_ctx_t *)c;
    ctx->len = 0;
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
    static const uint8_t salt[8] = {0};
    makwa_hash(ctx->buf, ctx->len, salt, sizeof(salt),
               MAKWA_OPS_WORK_FACTOR, out, 32);
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
#endif /* NEXTSSL_HAS_MAKWA */
