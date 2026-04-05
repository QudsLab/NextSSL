/* pomelo_ops.c — hash_ops_t stub for Pomelo (Plan 205)
 *
 * Pomelo source (Hongjun Wu, public domain) is not yet available in this tree.
 * This file provides the extern declaration only.
 *
 * When NEXTSSL_HAS_POMELO is defined (and pomelo.c is present), this stub
 * will be replaced by a full accumulator wrapper following the same pattern
 * as catena_ops.c and lyra2_ops.c.
 *
 * Suggested parameters when implementing:
 *   outlen = 32, t_cost = 1, m_cost = 14 (16 MiB)
 */
#include "../../interface/hash_registry.h"

#ifdef NEXTSSL_HAS_POMELO
#include "pomelo.h"
#include "../../../common/secure_zero.h"
#include <string.h>
#include <stdint.h>

typedef struct {
    uint8_t buf[2040];
    size_t  len;
} pomelo_ops_ctx_t;

static void pomelo_ops_init(void *c) {
    pomelo_ops_ctx_t *ctx = (pomelo_ops_ctx_t *)c;
    ctx->len = 0;
}

static void pomelo_ops_update(void *c, const uint8_t *d, size_t l) {
    pomelo_ops_ctx_t *ctx = (pomelo_ops_ctx_t *)c;
    size_t room = sizeof(ctx->buf) - ctx->len;
    if (l > room) l = room;
    memcpy(ctx->buf + ctx->len, d, l);
    ctx->len += l;
}

static void pomelo_ops_final(void *c, uint8_t *out) {
    pomelo_ops_ctx_t *ctx = (pomelo_ops_ctx_t *)c;
    static const uint8_t salt[8] = {0};
    PHS(out, 32, ctx->buf, ctx->len, salt, sizeof(salt), 1, 14);
    secure_zero(ctx->buf, ctx->len);
    ctx->len = 0;
}

const hash_ops_t pomelo_ops = {
    .name        = "pomelo",
    .digest_size = 32,
    .block_size  = 64,
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED,
    .init        = pomelo_ops_init,
    .update      = pomelo_ops_update,
    .final       = pomelo_ops_final,
    .wu_per_eval = 16384.0,
    .mu_per_eval = 16.0,    /* 2^14 KiB = 16 MiB at m_cost=14 */
    .parallelism = 1
};
#endif /* NEXTSSL_HAS_POMELO */
