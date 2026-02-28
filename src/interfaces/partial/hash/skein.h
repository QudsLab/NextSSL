/**
 * @file skein.h
 * @brief Layer 1 (Partial) - Skein Hash Function Interface
 * 
 * @visibility HIDDEN (NEXTSSL_PARTIAL_API)
 * @layer 1
 * @category hash
 * @subcategory skein
 * 
 * This interface provides Skein hash function - SHA-3 finalist.
 * Skein is based on Threefish block cipher in Unique Block Iteration (UBI) mode.
 * 
 * Security properties:
 * - High security margin (72 rounds)
 * - Variable output length (arbitrary)
 * - Built-in MAC, KDF, and personalization modes
 * - Very fast on 64-bit platforms
 * 
 * @warning Skein is NOT standardized (SHA-3 finalist, not winner)
 * @warning Less widely deployed than SHA-2/SHA-3/BLAKE2
 * @warning Use for compatibility with existing Skein implementations
 * 
 * Thread safety: Each hash instance is NOT thread-safe.
 */

#ifndef NEXTSSL_PARTIAL_HASH_SKEIN_H
#define NEXTSSL_PARTIAL_HASH_SKEIN_H

#include <stddef.h>
#include <stdint.h>
#include "../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nextssl_partial_hash_skein_ctx nextssl_partial_hash_skein_ctx_t;

typedef enum {
    NEXTSSL_SKEIN_256,      /**< Skein-256 (32-byte state) */
    NEXTSSL_SKEIN_512,      /**< Skein-512 (64-byte state) */
    NEXTSSL_SKEIN_1024      /**< Skein-1024 (128-byte state) */
} nextssl_skein_variant_t;

#define NEXTSSL_SKEIN_256_BLOCK_BYTES   32
#define NEXTSSL_SKEIN_512_BLOCK_BYTES   64
#define NEXTSSL_SKEIN_1024_BLOCK_BYTES  128

NEXTSSL_PARTIAL_API size_t
nextssl_partial_hash_skein_ctx_size(nextssl_skein_variant_t variant);

NEXTSSL_PARTIAL_API int
nextssl_partial_hash_skein_init(
    nextssl_partial_hash_skein_ctx_t *ctx,
    nextssl_skein_variant_t variant,
    size_t output_bits
);

NEXTSSL_PARTIAL_API int
nextssl_partial_hash_skein_init_ext(
    nextssl_partial_hash_skein_ctx_t *ctx,
    nextssl_skein_variant_t variant,
    size_t output_bits,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *personalization,
    size_t personalization_len
);

NEXTSSL_PARTIAL_API int
nextssl_partial_hash_skein_update(
    nextssl_partial_hash_skein_ctx_t *ctx,
    const uint8_t *data,
    size_t data_len
);

NEXTSSL_PARTIAL_API int
nextssl_partial_hash_skein_final(
    nextssl_partial_hash_skein_ctx_t *ctx,
    uint8_t *output
);

NEXTSSL_PARTIAL_API void
nextssl_partial_hash_skein_destroy(nextssl_partial_hash_skein_ctx_t *ctx);

NEXTSSL_PARTIAL_API int
nextssl_partial_hash_skein(
    nextssl_skein_variant_t variant,
    const uint8_t *data,
    size_t data_len,
    uint8_t *output,
    size_t output_bits
);

NEXTSSL_PARTIAL_API int
nextssl_partial_hash_skein_selftest(nextssl_skein_variant_t variant);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_HASH_SKEIN_H */
