/* hc128.h — HC-128 stream cipher (eSTREAM portfolio, Profile 1 winner)
 *
 * HC-128 uses two tables P[512] and Q[512] of 32-bit words, updated
 * and output at 1 word per step using non-linear feedback functions.
 * Key: 128 bits.  IV: 128 bits.
 *
 * Reference: https://www.ecrypt.eu.org/stream/hcpf.html
 *            Wu, "The Stream Cipher HC-128", 2008
 */
#ifndef NEXTSSL_HC128_H
#define NEXTSSL_HC128_H

#include <stdint.h>
#include <stddef.h>

#define HC128_KEY_SIZE  16u  /* 128-bit key */
#define HC128_IV_SIZE   16u  /* 128-bit IV  */

typedef struct {
    uint32_t P[512];
    uint32_t Q[512];
    uint32_t cnt;       /* global counter (0..1023) */
} hc128_ctx;

/* hc128_init — Initialize HC-128 with key and IV.
 * Returns 0 on success. */
int hc128_init(hc128_ctx    *ctx,
                const uint8_t key[HC128_KEY_SIZE],
                const uint8_t iv[HC128_IV_SIZE]);

/* hc128_keystream — Generate keystream into buf. */
void hc128_keystream(hc128_ctx *ctx, uint8_t *buf, size_t len);

/* hc128_xor — XOR keystream with in[] → out[]. */
void hc128_xor(hc128_ctx *ctx,
                const uint8_t *in, uint8_t *out, size_t len);

#endif /* NEXTSSL_HC128_H */
