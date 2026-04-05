/* sm3.h — SM3 hash (GB/T 32905-2016)
 *
 * SM3 is the Chinese national standard 256-bit hash function.
 * Block: 64 bytes.  Digest: 32 bytes.
 *
 * Implementation: vendored GmSSL source (Apache-2.0 licence).
 *
 * This header exposes the GmSSL SM3_CTX directly (from sm3_gmssl.h) and adds
 * two conventions used by this project:
 *   - sm3_final()  — alias for GmSSL's sm3_finish()
 *   - sm3_hash()   — one-shot convenience function
 *
 * sm3_init() and sm3_update() are provided directly by the GmSSL header
 * (with identical signatures).
 */
#ifndef SM3_H
#define SM3_H

#include <stddef.h>
#include <stdint.h>
#include "sm3_gmssl.h"   /* provides SM3_CTX, sm3_init, sm3_update, sm3_finish */

#ifdef __cplusplus
extern "C" {
#endif

#define SM3_DIGEST_LENGTH  SM3_DIGEST_SIZE  /* 32 */
#define SM3_BLOCK_LEN      SM3_BLOCK_SIZE   /* 64 */

/**
 * Finalise: alias for GmSSL's sm3_finish — erases ctx and writes 32 bytes.
 */
void sm3_final(SM3_CTX *ctx, uint8_t out[SM3_DIGEST_LENGTH]);

/**
 * One-shot: hash |datalen| bytes of |data| into the 32-byte |out|.
 */
void sm3_hash(const uint8_t *data, size_t datalen,
              uint8_t out[SM3_DIGEST_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif /* SM3_H */
