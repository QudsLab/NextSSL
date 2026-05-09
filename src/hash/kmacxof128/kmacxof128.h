/* kmacxof128.h — KMACXOF-128 (SP 800-185 §4.3.1 XOF variant)
 *
 * KMACXOF128 is identical to KMAC128 except the output-length encoding
 * uses right_encode(0) instead of right_encode(L), enabling unlimited
 * squeezable output (XOF mode).
 *
 * Reuses KMAC_CTX and kmac streaming machinery from kmac.h.
 */
#ifndef KMACXOF128_H
#define KMACXOF128_H

#include <stddef.h>
#include <stdint.h>
#include "../kmac/kmac.h"

/* KMACXOF128_CTX is the same underlying context as KMAC_CTX */
typedef KMAC_CTX KMACXOF128_CTX;

/* Streaming interface
 * key / custom may be NULL / 0 for empty key / customization. */
void kmacxof128_init  (KMACXOF128_CTX *ctx,
                       const uint8_t *key,    size_t klen,
                       const uint8_t *custom, size_t clen);
void kmacxof128_update(KMACXOF128_CTX *ctx, const uint8_t *data, size_t dlen);

/* Finalise and squeeze outlen bytes.  Uses right_encode(0) per SP 800-185. */
void kmacxof128_final (KMACXOF128_CTX *ctx, uint8_t *out, size_t outlen);

/* One-shot: hash key || data, produce outlen bytes of output. */
int  kmacxof128_compute(const uint8_t *key,    size_t klen,
                        const uint8_t *data,   size_t dlen,
                        const uint8_t *custom, size_t clen,
                        uint8_t *out, size_t outlen);

/* hash_ops_t-compatible unkeyed init (empty key, empty custom, 32-byte out) */
void kmacxof128_ops_init_fn(KMACXOF128_CTX *ctx);

#endif /* KMACXOF128_H */
