/* salsa20.h — Salsa20 stream cipher (eSTREAM portfolio)
 *
 * Salsa20 by D. J. Bernstein, based on a 20-round ARX design.
 * Key sizes: 128-bit or 256-bit.  Nonce: 8 bytes.  Counter: 64-bit.
 *
 * Reference: https://cr.yp.to/snuffle/spec.pdf
 *            https://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/salsa20/
 */
#ifndef NEXTSSL_SALSA20_H
#define NEXTSSL_SALSA20_H

#include <stdint.h>
#include <stddef.h>

#define SALSA20_KEY128_SIZE  16u
#define SALSA20_KEY256_SIZE  32u
#define SALSA20_NONCE_SIZE    8u
#define SALSA20_BLOCK_SIZE   64u

typedef struct {
    uint32_t state[16];
} salsa20_ctx;

/* salsa20_init — Initialize Salsa20 context.
 * key     : 16 or 32 byte key
 * key_len : 16 or 32
 * nonce   : 8-byte nonce
 * counter : initial block counter (typically 0)
 * Returns 0 on success, -1 on error. */
int salsa20_init(salsa20_ctx *ctx,
                  const uint8_t *key, size_t key_len,
                  const uint8_t  nonce[SALSA20_NONCE_SIZE],
                  uint64_t       counter);

/* salsa20_xor — XOR keystream with in[] → out[].
 * in and out may alias (in-place). */
void salsa20_xor(salsa20_ctx *ctx,
                  const uint8_t *in, uint8_t *out, size_t len);

/* salsa20_keystream — Write raw keystream into buf. */
void salsa20_keystream(salsa20_ctx *ctx, uint8_t *buf, size_t len);

#endif /* NEXTSSL_SALSA20_H */
