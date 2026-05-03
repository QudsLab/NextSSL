/* hmac.h — HMAC over hash_ops_t vtable (Plan 202 / Plan 204)
 *
 * Implements RFC 2104:
 *   HMAC(K, m) = H((K ⊕ opad) ‖ H((K ⊕ ipad) ‖ m))
 *
 * Works with any hash registered in the hash registry.
 * ipad/opad buffers are wiped before returning (Plan 204).
 */
#ifndef HMAC_H
#define HMAC_H

#include <stddef.h>
#include <stdint.h>
#include "hash_ops.h"

/* -------------------------------------------------------------------------
 * One-shot HMAC computation
 * -------------------------------------------------------------------------
 * hash    — algorithm vtable (e.g. &sha256_ops, &blake3_ops)
 * key     — MAC key bytes
 * klen    — key length in bytes
 * data    — message bytes
 * dlen    — message length
 * out     — caller-allocated buffer of at least hash->digest_size bytes
 *
 * Returns 0 on success, -1 on invalid arguments.
 */
int hmac_compute(const hash_ops_t *hash,
                 const uint8_t    *key,  size_t klen,
                 const uint8_t    *data, size_t dlen,
                 uint8_t          *out);

/* -------------------------------------------------------------------------
 * Streaming HMAC
 * -------------------------------------------------------------------------
 * Use these when the message is produced incrementally.
 *
 * hmac_ctx_t — opaque context; declare on the stack.
 */
typedef struct {
    const hash_ops_t *hash;
    uint8_t           opad[HASH_OPS_MAX_BLOCK];
    /* inner context follows — sized for the largest supported hash */
    uint8_t           inner_ctx[HASH_OPS_CTX_MAX];
} hmac_ctx_t;

/* Returns 0 on success, -1 on invalid arguments. */
int hmac_init  (hmac_ctx_t *ctx, const hash_ops_t *hash,
                const uint8_t *key, size_t klen);
int hmac_update(hmac_ctx_t *ctx, const uint8_t *data, size_t len);
/* Writes hash->digest_size bytes to out; wipes ipad/opad before returning. */
int hmac_final (hmac_ctx_t *ctx, uint8_t *out);

/* -------------------------------------------------------------------------
 * hmac_compute_adapter — HMAC using a hash_adapter_t
 * -------------------------------------------------------------------------
 * Works with any hash_adapter_t (plain hash or KDF adapter).
 * Uses ha->block_size for ipad/opad padding and ha->digest_size for
 * the inner digest buffer.
 *
 * ha      — pre-configured adapter (init_fn/update_fn/final_fn must be set)
 * key     — MAC key bytes
 * klen    — key length in bytes
 * data    — message bytes
 * dlen    — message length
 * out     — caller-allocated output buffer (at least ha->digest_size bytes)
 * out_len — size of out buffer
 *
 * Returns 0 on success, -1 on invalid arguments, -2 on internal error.
 * -------------------------------------------------------------------------*/
#include "hash_adapter.h"
int hmac_compute_adapter(const hash_adapter_t *ha,
                         const uint8_t        *key,  size_t klen,
                         const uint8_t        *data, size_t dlen,
                         uint8_t              *out,  size_t out_len);

#endif /* HMAC_H */
