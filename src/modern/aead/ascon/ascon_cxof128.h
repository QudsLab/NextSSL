/* ascon_cxof128.h — Ascon-CXOF128 customizable XOF (SP 800-232) */
#ifndef NEXTSSL_ASCON_CXOF128_H
#define NEXTSSL_ASCON_CXOF128_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t x[5];
    uint8_t  buf[8];
    size_t   buf_len;
    int      squeezing;
} ascon_cxof128_ctx_t;

/* Z: customization string (may be NULL / 0 for empty) */
void ascon_cxof128_init  (ascon_cxof128_ctx_t *ctx,
                           const uint8_t *Z, size_t Zlen);
void ascon_cxof128_absorb(ascon_cxof128_ctx_t *ctx, const uint8_t *in, size_t inlen);
void ascon_cxof128_squeeze(ascon_cxof128_ctx_t *ctx, uint8_t *out, size_t outlen);

/* One-shot */
void ascon_cxof128(const uint8_t *Z, size_t Zlen,
                   const uint8_t *msg, size_t msglen,
                   uint8_t *out, size_t outlen);

#endif /* NEXTSSL_ASCON_CXOF128_H */
