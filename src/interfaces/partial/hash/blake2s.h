/**
 * @file blake2s.h
 * @brief Layer 1 (Partial) - BLAKE2s Hash Function Interface
 * 
 * @visibility HIDDEN (NEXTSSL_PARTIAL_API)
 * @layer 1
 * @category hash
 * @subcategory blake2s
 * 
 * This interface provides BLAKE2s (32-bit optimized) hash function (RFC 7693).
 * BLAKE2s is optimized for 8-32 bit platforms and produces up to 32-byte output.
 * 
 * @warning Use BLAKE2b for 64-bit platforms (faster)
 * @warning Use BLAKE2s for 32-bit platforms or when output <= 32 bytes
 * 
 * Thread safety: Each hash instance is NOT thread-safe.
 */

#ifndef NEXTSSL_PARTIAL_HASH_BLAKE2S_H
#define NEXTSSL_PARTIAL_HASH_BLAKE2S_H

#include <stddef.h>
#include <stdint.h>
#include "../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nextssl_partial_hash_blake2s_ctx nextssl_partial_hash_blake2s_ctx_t;

#define NEXTSSL_BLAKE2S_BLOCKBYTES    64    /**< Block size */
#define NEXTSSL_BLAKE2S_OUTBYTES      32    /**< Maximum output size */
#define NEXTSSL_BLAKE2S_KEYBYTES      32    /**< Maximum key size */
#define NEXTSSL_BLAKE2S_SALTBYTES     8     /**< Salt size */
#define NEXTSSL_BLAKE2S_PERSONALBYTES 8     /**< Personalization size */

NEXTSSL_PARTIAL_API size_t
nextssl_partial_hash_blake2s_ctx_size(void);

NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake2s_init(
    nextssl_partial_hash_blake2s_ctx_t *ctx,
    size_t output_len,
    const uint8_t *key,
    size_t key_len
);

NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake2s_init_full(
    nextssl_partial_hash_blake2s_ctx_t *ctx,
    size_t output_len,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *salt,
    const uint8_t *personal
);

NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake2s_update(
    nextssl_partial_hash_blake2s_ctx_t *ctx,
    const uint8_t *data,
    size_t data_len
);

NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake2s_final(
    nextssl_partial_hash_blake2s_ctx_t *ctx,
    uint8_t *output
);

NEXTSSL_PARTIAL_API void
nextssl_partial_hash_blake2s_destroy(nextssl_partial_hash_blake2s_ctx_t *ctx);

NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake2s(
    const uint8_t *data,
    size_t data_len,
    uint8_t *output,
    size_t output_len
);

NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake2s_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_HASH_BLAKE2S_H */
