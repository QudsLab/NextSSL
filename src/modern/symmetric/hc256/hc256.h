/* hc256.h — HC-256 stream cipher (extended HC-128 with 256-bit key/IV)
 *
 * HC-256 extends HC-128 to 256-bit keys and IVs, with tables P[1024] and Q[1024].
 *
 * Reference: https://www.ecrypt.eu.org/stream/hcpf.html
 *            Wu, "A New Stream Cipher HC-256", FSE 2004
 */
#ifndef NEXTSSL_HC256_H
#define NEXTSSL_HC256_H

#include <stdint.h>
#include <stddef.h>

#define HC256_KEY_SIZE  32u  /* 256-bit key */
#define HC256_IV_SIZE   32u  /* 256-bit IV  */

typedef struct {
    uint32_t P[1024];
    uint32_t Q[1024];
    uint32_t cnt;       /* step counter (0..2047) */
} hc256_ctx;

/* hc256_init — Initialize HC-256.
 * Returns 0 on success. */
int hc256_init(hc256_ctx    *ctx,
                const uint8_t key[HC256_KEY_SIZE],
                const uint8_t iv[HC256_IV_SIZE]);

void hc256_keystream(hc256_ctx *ctx, uint8_t *buf, size_t len);
void hc256_xor(hc256_ctx *ctx,
                const uint8_t *in, uint8_t *out, size_t len);

#endif /* NEXTSSL_HC256_H */
