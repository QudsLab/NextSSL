/* rabbit.h — Rabbit stream cipher (eSTREAM portfolio)
 *
 * Rabbit is a 128-bit key, 64-bit IV synchronous stream cipher operating
 * at 3.7 cycles/byte on modern x86.  It uses 8 counters + 8 state words.
 *
 * Reference: https://www.ecrypt.eu.org/stream/rabbitpf.html
 *            Boesgaard et al., "The Rabbit Stream Cipher", 2003
 */
#ifndef NEXTSSL_RABBIT_H
#define NEXTSSL_RABBIT_H

#include <stdint.h>
#include <stddef.h>

#define RABBIT_KEY_SIZE  16u  /* 128-bit key */
#define RABBIT_IV_SIZE    8u  /* 64-bit IV   */

typedef struct {
    uint32_t x[8];   /* state variables */
    uint32_t c[8];   /* counter variables */
    uint32_t carry;  /* carry bit */
} rabbit_ctx;

/* rabbit_init — Set up Rabbit state with key (no IV).
 * Returns 0 on success. */
int rabbit_init(rabbit_ctx *ctx, const uint8_t key[RABBIT_KEY_SIZE]);

/* rabbit_set_iv — Optionally set IV (64 bits).  Call after rabbit_init.
 * If not called, the IV is zero. */
void rabbit_set_iv(rabbit_ctx *ctx, const uint8_t iv[RABBIT_IV_SIZE]);

void rabbit_keystream(rabbit_ctx *ctx, uint8_t *buf, size_t len);
void rabbit_xor(rabbit_ctx *ctx,
                 const uint8_t *in, uint8_t *out, size_t len);

#endif /* NEXTSSL_RABBIT_H */
