/* kmac.h — KMAC-128 and KMAC-256 (NIST SP 800-185)
 *
 * KMAC is a Keccak-based MAC and PRF built on cSHAKE.
 * KMAC128 uses cSHAKE128 (rate=168); KMAC256 uses cSHAKE256 (rate=136).
 *
 * Two interfaces are provided:
 *
 *  1. One-shot keyed MAC:
 *       kmac128_compute(key, klen, data, dlen, custom, clen, out, outlen)
 *       kmac256_compute(...)
 *     These follow the SP 800-185 §4.3.1 KMAC definition exactly.
 *
 *  2. hash_ops_t-compatible unkeyed variant (used via hash registry):
 *     KMAC with empty key and empty customization string is a valid hash
 *     primitive — it is equivalent to cSHAKE with N="KMAC", S="".
 *     The hash_ops_t wrappers (kmac128_ops, kmac256_ops) use this form.
 *     Streaming via KMAC_CTX works the same way:
 *       kmac128_init(ctx, key, klen, custom, clen)  — keyed streaming
 *       kmac_update(ctx, data, dlen)
 *       kmac_final(ctx, out, outlen)
 */
#ifndef KMAC_H
#define KMAC_H

#include <stddef.h>
#include <stdint.h>
#include "shake.h"

/* -------------------------------------------------------------------------
 * Streaming context
 * -------------------------------------------------------------------------
 * Fits in HASH_OPS_CTX_MAX (2048 bytes).
 */
typedef struct {
    SHAKE_CTX shake;
    size_t    out_bytes;  /* fixed output length for this instance */
} KMAC_CTX;

/* Streaming keyed KMAC
 * custom / clen may be NULL / 0 for empty customization. */
void kmac128_init  (KMAC_CTX *ctx,
                    const uint8_t *key,    size_t klen,
                    const uint8_t *custom, size_t clen);
void kmac256_init  (KMAC_CTX *ctx,
                    const uint8_t *key,    size_t klen,
                    const uint8_t *custom, size_t clen);
void kmac_update   (KMAC_CTX *ctx, const uint8_t *data, size_t dlen);
/* Writes ctx->out_bytes to out; finalizes the context. */
void kmac_final    (KMAC_CTX *ctx, uint8_t *out);

/* -------------------------------------------------------------------------
 * One-shot keyed KMAC (SP 800-185 §4.3.1)
 * outlen is the desired output length in bytes.
 * Returns 0 on success, -1 on invalid arguments.
 * -------------------------------------------------------------------------*/
int kmac128_compute(const uint8_t *key,    size_t klen,
                    const uint8_t *data,   size_t dlen,
                    const uint8_t *custom, size_t clen,
                    uint8_t *out, size_t outlen);

int kmac256_compute(const uint8_t *key,    size_t klen,
                    const uint8_t *data,   size_t dlen,
                    const uint8_t *custom, size_t clen,
                    uint8_t *out, size_t outlen);

/* -------------------------------------------------------------------------
 * hash_ops_t-compatible unkeyed init helpers
 * (used by hash_registry.c wrappers — empty key, empty customization)
 * -------------------------------------------------------------------------*/
void kmac128_ops_init_fn(KMAC_CTX *ctx);   /* 32-byte output */
void kmac256_ops_init_fn(KMAC_CTX *ctx);   /* 64-byte output */

#endif /* KMAC_H */
