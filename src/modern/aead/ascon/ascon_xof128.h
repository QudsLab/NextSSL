/* ascon_xof128.h — Ascon-XOF128 (SP 800-232)
 * Extendable-output function with 128-bit capacity. */
#ifndef NEXTSSL_ASCON_XOF128_H
#define NEXTSSL_ASCON_XOF128_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t x[5];
    uint8_t  buf[8];
    size_t   buf_len;
    int      squeezing;
} ascon_xof128_ctx_t;

void ascon_xof128_init  (ascon_xof128_ctx_t *ctx);
void ascon_xof128_absorb(ascon_xof128_ctx_t *ctx, const uint8_t *in,  size_t inlen);
void ascon_xof128_squeeze(ascon_xof128_ctx_t *ctx, uint8_t *out, size_t outlen);

/* One-shot */
void ascon_xof128(const uint8_t *msg, size_t msglen, uint8_t *out, size_t outlen);

#endif /* NEXTSSL_ASCON_XOF128_H */
