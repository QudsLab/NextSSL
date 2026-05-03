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
#include "../interface/hash_registry.h"

#include "pomelo.h"
#include "../../common/secure_zero.h"
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
} pomelo_ops_ctx_t;

static void pomelo_ops_init(void *c) {
    pomelo_ops_ctx_t *ctx = (pomelo_ops_ctx_t *)c;
    ctx->len = 0;
    /* salt field intentionally NOT reset — survives across init calls */
}

/* pomelo_ops_set_salt — configure override salt before init/update/final (Plan 40003)
 * Pass NULL or salt_len=0 to revert to the domain-separator default. */
void pomelo_ops_set_salt(void *ctx_raw, const uint8_t *salt, size_t salt_len)
{
    pomelo_ops_ctx_t *ctx = (pomelo_ops_ctx_t *)ctx_raw;
    if (!ctx || !salt || salt_len == 0) {
        if (ctx) ctx->salt_len = 0;
        return;
    }
    size_t copy = salt_len > sizeof(ctx->salt) ? sizeof(ctx->salt) : salt_len;
    memcpy(ctx->salt, salt, copy);
    ctx->salt_len = (uint8_t)copy;
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
    /* Domain separator — default when no salt configured (Plan 40003). */
    static const uint8_t s_default[8] = {'N','X','T','S','P','M','L', 0};
    const uint8_t *s   = ctx->salt_len ? ctx->salt : s_default;
    size_t         sln = ctx->salt_len ? ctx->salt_len : sizeof(s_default);
    PHS(out, 32, ctx->buf, ctx->len, s, sln, 1, 14);
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
