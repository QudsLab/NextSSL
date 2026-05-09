/* kmacxof256.h — KMACXOF-256 (SP 800-185 §4.3.1 XOF variant, 256-bit security)
 *
 * KMACXOF256 is identical to KMAC256 except uses right_encode(0) for XOF mode.
 * Reuses KMAC_CTX and kmac streaming machinery from kmac.h.
 */
#ifndef KMACXOF256_H
#define KMACXOF256_H

#include <stddef.h>
#include <stdint.h>
#include "../kmac/kmac.h"

/* KMACXOF256_CTX is the same underlying context as KMAC_CTX */
typedef KMAC_CTX KMACXOF256_CTX;

void kmacxof256_init  (KMACXOF256_CTX *ctx,
                       const uint8_t *key,    size_t klen,
                       const uint8_t *custom, size_t clen);
void kmacxof256_update(KMACXOF256_CTX *ctx, const uint8_t *data, size_t dlen);
void kmacxof256_final (KMACXOF256_CTX *ctx, uint8_t *out, size_t outlen);

int  kmacxof256_compute(const uint8_t *key,    size_t klen,
                        const uint8_t *data,   size_t dlen,
                        const uint8_t *custom, size_t clen,
                        uint8_t *out, size_t outlen);

void kmacxof256_ops_init_fn(KMACXOF256_CTX *ctx);

#endif /* KMACXOF256_H */
