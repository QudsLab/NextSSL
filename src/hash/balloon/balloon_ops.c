/* balloon_ops.c — hash_ops_t wrapper for Balloon (Plan 40004.2)
 *
 * Provides the hash_ops_t interface for balloon hashing using the
 * balloon library's hash_state_* functions directly (single-threaded path,
 * which is what the hash_ops accumulator pattern needs).
 *
 * Suggested parameters:
 *   s_cost = 1024 blocks, t_cost = 3 mixing rounds, n_threads = 1
 */
#include "../interface/hash_registry.h"
#include "constants.h"     /* SALT_LEN (32), BLOCK_SIZE, n_threads defaults */
#include "hash_state.h"    /* hash_state_init/fill/mix/extract/free */
#include "balloon.h"       /* struct balloon_options */
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
} balloon_ops_ctx_t;

static void balloon_ops_init(void *c) {
    balloon_ops_ctx_t *ctx = (balloon_ops_ctx_t *)c;
    ctx->len = 0;
    /* salt field intentionally NOT reset — survives across init calls */
}

/* balloon_ops_set_salt — configure override salt before init/update/final (Plan 40003).
 * Pass NULL or salt_len=0 to revert to the domain-separator default. */
void balloon_ops_set_salt(void *ctx_raw, const uint8_t *salt, size_t salt_len)
{
    balloon_ops_ctx_t *ctx = (balloon_ops_ctx_t *)ctx_raw;
    if (!ctx || !salt || salt_len == 0) {
        if (ctx) ctx->salt_len = 0;
        return;
    }
    size_t copy = salt_len > sizeof(ctx->salt) ? sizeof(ctx->salt) : salt_len;
    memcpy(ctx->salt, salt, copy);
    ctx->salt_len = (uint8_t)copy;
}

static void balloon_ops_update(void *c, const uint8_t *d, size_t l) {
    balloon_ops_ctx_t *ctx = (balloon_ops_ctx_t *)c;
    size_t room = sizeof(ctx->buf) - ctx->len;
    if (l > room) l = room;
    memcpy(ctx->buf + ctx->len, d, l);
    ctx->len += l;
}

#define BALLOON_OPS_S_COST    1024   /* memory blocks (1 KiB each) */
#define BALLOON_OPS_T_COST       3   /* mixing rounds */

static void balloon_ops_final(void *c, uint8_t *out) {
    balloon_ops_ctx_t *ctx = (balloon_ops_ctx_t *)c;

    /* Domain separator — default when no salt configured (Plan 40003). */
    static const uint8_t s_default[8] = {'N','X','T','S','B','L','N', 0};
    const uint8_t *s   = ctx->salt_len ? ctx->salt : s_default;
    size_t         sln = ctx->salt_len ? ctx->salt_len : sizeof(s_default);

    /* Balloon hash_state_init requires exactly SALT_LEN=32 bytes.
     * Derive a 32-byte salt by padding/hashing the configured salt. */
    uint8_t full_salt[SALT_LEN];
    memset(full_salt, 0, SALT_LEN);
    size_t copy = sln > SALT_LEN ? SALT_LEN : sln;
    memcpy(full_salt, s, copy);

    struct balloon_options opts = {
        .s_cost    = BALLOON_OPS_S_COST,
        .t_cost    = BALLOON_OPS_T_COST,
        .n_threads = 1
    };

    struct hash_state hs;
    if (hash_state_init(&hs, &opts, full_salt) != 0) {
        memset(out, 0, 32);
        goto cleanup;
    }
    if (hash_state_fill(&hs, full_salt, ctx->buf, ctx->len) != 0) {
        hash_state_free(&hs);
        memset(out, 0, 32);
        goto cleanup;
    }
    for (uint32_t i = 0; i < BALLOON_OPS_T_COST; i++)
        hash_state_mix(&hs);

    /* BLOCK_SIZE is the output size (32 bytes on SHA-256 balloon). */
    uint8_t raw[BLOCK_SIZE];
    hash_state_extract(&hs, raw);
    hash_state_free(&hs);

    size_t copy_out = sizeof(raw) < 32 ? sizeof(raw) : 32;
    memcpy(out, raw, copy_out);
    if (copy_out < 32) memset(out + copy_out, 0, 32 - copy_out);
    secure_zero(raw, sizeof(raw));

cleanup:
    secure_zero(full_salt, sizeof(full_salt));
    secure_zero(ctx->buf, ctx->len);
    ctx->len = 0;
}

const hash_ops_t balloon_ops = {
    .name        = "balloon",
    .digest_size = 32,
    .block_size  = 64,
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED,
    .init        = balloon_ops_init,
    .update      = balloon_ops_update,
    .final       = balloon_ops_final,
    .wu_per_eval = 3072.0,    /* t_cost × s_cost blocks */
    .mu_per_eval = 1024.0,    /* s_cost blocks × 1 KiB ≈ 1 MiB */
    .parallelism = 1
};
