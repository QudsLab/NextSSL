/* hmac.c — HMAC over hash_ops_t vtable (RFC 2104, Plan 202 / Plan 204)
 *
 * Memory discipline (Plan 204):
 *   All intermediate key material (kbuf, ipad, opad, inner digest) is wiped
 *   via secure_zero() before the function returns on every code path.
 */
#include "hmac.h"
#include "../../common/secure_zero.h"

#include <string.h>
#include <stdint.h>

/* -------------------------------------------------------------------------
 * Internal helper: compute one HMAC invocation on contiguous data.
 * Called by both hmac_compute() and hmac_final().
 * Caller guarantees hash != NULL.
 * -------------------------------------------------------------------------*/
static int hmac_compute_inner(const hash_ops_t *hash,
                               const uint8_t    *key,  size_t klen,
                               const uint8_t    *data, size_t dlen,
                               uint8_t          *out)
{
    if (!key || !out) return -1;
    if (klen == 0 || hash->block_size > HASH_OPS_MAX_BLOCK) return -1;

    uint8_t kbuf[HASH_OPS_MAX_BLOCK];  /* normalised key ≤ block_size bytes */
    uint8_t ipad[HASH_OPS_MAX_BLOCK];
    uint8_t opad[HASH_OPS_MAX_BLOCK];
    uint8_t inner_ctx[HASH_OPS_CTX_MAX];
    uint8_t inner_digest[HASH_OPS_MAX_BLOCK]; /* max digest ≤ 64 bytes */

    /* Keys longer than the block are hashed first (RFC 2104 §3) */
    if (klen > hash->block_size) {
        hash->init(inner_ctx);
        hash->update(inner_ctx, key, klen);
        hash->final(inner_ctx, kbuf);
        klen = hash->digest_size;
    } else {
        memcpy(kbuf, key, klen);
    }
    /* Zero-pad to block size */
    if (klen < hash->block_size)
        memset(kbuf + klen, 0, hash->block_size - klen);

    /* Build ipad / opad */
    for (size_t i = 0; i < hash->block_size; i++) {
        ipad[i] = kbuf[i] ^ 0x36u;
        opad[i] = kbuf[i] ^ 0x5cu;
    }

    /* Inner hash: H(ipad ‖ data) */
    hash->init(inner_ctx);
    hash->update(inner_ctx, ipad, hash->block_size);
    if (data && dlen > 0)
        hash->update(inner_ctx, data, dlen);
    hash->final(inner_ctx, inner_digest);

    /* Outer hash: H(opad ‖ inner_digest) */
    hash->init(inner_ctx);
    hash->update(inner_ctx, opad, hash->block_size);
    hash->update(inner_ctx, inner_digest, hash->digest_size);
    hash->final(inner_ctx, out);

    /* Wipe secrets (Plan 204) */
    secure_zero(kbuf,         sizeof(kbuf));
    secure_zero(ipad,         sizeof(ipad));
    secure_zero(opad,         sizeof(opad));
    secure_zero(inner_ctx,    sizeof(inner_ctx));
    secure_zero(inner_digest, sizeof(inner_digest));
    return 0;
}

/* =========================================================================
 * One-shot HMAC
 * ========================================================================= */
int hmac_compute(const hash_ops_t *hash,
                 const uint8_t    *key,  size_t klen,
                 const uint8_t    *data, size_t dlen,
                 uint8_t          *out)
{
    if (!hash || !data || dlen == 0) return -1;
    if (!(hash->usage_flags & HASH_USAGE_HMAC)) return -1;
    return hmac_compute_inner(hash, key, klen, data, dlen, out);
}

/* =========================================================================
 * Streaming HMAC
 * ========================================================================= */
int hmac_init(hmac_ctx_t *ctx, const hash_ops_t *hash,
              const uint8_t *key, size_t klen)
{
    if (!ctx || !hash || !key || klen == 0) return -1;
    if (!(hash->usage_flags & HASH_USAGE_HMAC)) return -1;
    if (hash->block_size > HASH_OPS_MAX_BLOCK) return -1;

    ctx->hash = hash;

    uint8_t kbuf[HASH_OPS_MAX_BLOCK];
    uint8_t ipad[HASH_OPS_MAX_BLOCK];

    if (klen > hash->block_size) {
        /* Hash the key down */
        uint8_t tmp[HASH_OPS_CTX_MAX];
        hash->init(tmp);
        hash->update(tmp, key, klen);
        hash->final(tmp, kbuf);
        klen = hash->digest_size;
        secure_zero(tmp, sizeof(tmp));
    } else {
        memcpy(kbuf, key, klen);
    }
    if (klen < hash->block_size)
        memset(kbuf + klen, 0, hash->block_size - klen);

    for (size_t i = 0; i < hash->block_size; i++) {
        ipad[i]       = kbuf[i] ^ 0x36u;
        ctx->opad[i]  = kbuf[i] ^ 0x5cu;
    }

    /* Start inner hash with ipad prefix */
    hash->init(ctx->inner_ctx);
    hash->update(ctx->inner_ctx, ipad, hash->block_size);

    secure_zero(kbuf, sizeof(kbuf));
    secure_zero(ipad, sizeof(ipad));
    return 0;
}

int hmac_update(hmac_ctx_t *ctx, const uint8_t *data, size_t len)
{
    if (!ctx || !ctx->hash || !data || len == 0) return -1;
    ctx->hash->update(ctx->inner_ctx, data, len);
    return 0;
}

int hmac_final(hmac_ctx_t *ctx, uint8_t *out)
{
    if (!ctx || !ctx->hash || !out) return -1;
    const hash_ops_t *h = ctx->hash;

    uint8_t inner_digest[HASH_OPS_MAX_BLOCK];
    uint8_t outer_ctx[HASH_OPS_CTX_MAX];

    /* Finish inner hash */
    h->final(ctx->inner_ctx, inner_digest);

    /* Outer hash: H(opad ‖ inner_digest) */
    h->init(outer_ctx);
    h->update(outer_ctx, ctx->opad, h->block_size);
    h->update(outer_ctx, inner_digest, h->digest_size);
    h->final(outer_ctx, out);

    /* Wipe (Plan 204) */
    secure_zero(inner_digest,  sizeof(inner_digest));
    secure_zero(outer_ctx,     sizeof(outer_ctx));
    secure_zero(ctx->opad,     sizeof(ctx->opad));
    secure_zero(ctx->inner_ctx, sizeof(ctx->inner_ctx));
    return 0;
}

/* =========================================================================
 * Adapter-based HMAC (Plan 40002)
 * ========================================================================= */
#include "../../hash/adapters/hash_adapter.h"

/* Maximum sizes for adapter-based HMAC internal buffers.
 * Adapters report actual sizes in ha->block_size / ha->digest_size. */
#define ADAPTER_MAX_BLOCK  256   /* generous upper bound across all supported algos */
#define ADAPTER_MAX_DIGEST 128

int hmac_compute_adapter(const hash_adapter_t *ha,
                         const uint8_t        *key,  size_t klen,
                         const uint8_t        *data, size_t dlen,
                         uint8_t              *out,  size_t out_len)
{
    if (!ha || !ha->init_fn || !ha->update_fn || !ha->final_fn) return -1;
    if (!key || klen == 0 || !data || !out || out_len == 0) return -1;

    size_t block_size  = ha->block_size  ? ha->block_size  : 64;
    size_t digest_size = ha->digest_size ? ha->digest_size : 32;
    if (block_size  > ADAPTER_MAX_BLOCK)  return -1;
    if (digest_size > ADAPTER_MAX_DIGEST) return -1;

    uint8_t kbuf[ADAPTER_MAX_BLOCK];
    uint8_t ipad[ADAPTER_MAX_BLOCK];
    uint8_t opad[ADAPTER_MAX_BLOCK];
    uint8_t inner[ADAPTER_MAX_DIGEST];

    /* Keys longer than block_size: hash them down */
    if (klen > block_size) {
        ha->init_fn(ha->impl);
        ha->update_fn(ha->impl, key, klen);
        ha->final_fn(ha->impl, kbuf, digest_size);
        klen = digest_size;
    } else {
        memcpy(kbuf, key, klen);
    }
    if (klen < block_size) memset(kbuf + klen, 0, block_size - klen);

    for (size_t i = 0; i < block_size; i++) {
        ipad[i] = kbuf[i] ^ 0x36u;
        opad[i] = kbuf[i] ^ 0x5cu;
    }

    /* Inner: H(ipad ‖ data) */
    ha->init_fn(ha->impl);
    ha->update_fn(ha->impl, ipad, block_size);
    ha->update_fn(ha->impl, data, dlen);
    ha->final_fn(ha->impl, inner, digest_size);

    /* Outer: H(opad ‖ inner) */
    ha->init_fn(ha->impl);
    ha->update_fn(ha->impl, opad, block_size);
    ha->update_fn(ha->impl, inner, digest_size);
    ha->final_fn(ha->impl, out, out_len);

    secure_zero(kbuf,  sizeof(kbuf));
    secure_zero(ipad,  sizeof(ipad));
    secure_zero(opad,  sizeof(opad));
    secure_zero(inner, sizeof(inner));
    return 0;
}
