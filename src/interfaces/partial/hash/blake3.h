/**
 * @file blake3.h
 * @brief Layer 1 (Partial) - BLAKE3 Hash Function Interface
 * 
 * @visibility HIDDEN (NEXTSSL_PARTIAL_API)
 * @layer 1
 * @category hash
 * @subcategory blake3
 * 
 * This interface provides BLAKE3 hash function - successor to BLAKE2.
 * BLAKE3 is extremely fast, parallelizable, and provides tree hashing.
 * 
 * Security properties:
 * - Same security as BLAKE2 (128-bit collision resistance)
 * - Much faster than BLAKE2 (especially on large inputs)
 * - Highly parallelizable (uses tree structure)
 * - Extendable output (like SHAKE)
 * - Built-in keyed mode and key derivation mode
 * 
 * @warning BLAKE3 is NOT standardized (no NIST/IETF standard yet)
 * @warning Use SHA-2/SHA-3 for regulatory compliance
 * @warning Use BLAKE3 for performance-critical applications
 * 
 * Thread safety: Each hash instance is NOT thread-safe.
 */

#ifndef NEXTSSL_PARTIAL_HASH_BLAKE3_H
#define NEXTSSL_PARTIAL_HASH_BLAKE3_H

#include <stddef.h>
#include <stdint.h>
#include "../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nextssl_partial_hash_blake3_ctx nextssl_partial_hash_blake3_ctx_t;

#define NEXTSSL_BLAKE3_OUT_LEN      32    /**< Default output length */
#define NEXTSSL_BLAKE3_KEY_LEN      32    /**< Key length for keyed mode */
#define NEXTSSL_BLAKE3_BLOCK_LEN    64    /**< Block size */
#define NEXTSSL_BLAKE3_CHUNK_LEN    1024  /**< Chunk size for tree hashing */

NEXTSSL_PARTIAL_API size_t
nextssl_partial_hash_blake3_ctx_size(void);

/**
 * @brief Initialize BLAKE3 context (hash mode)
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake3_init(nextssl_partial_hash_blake3_ctx_t *ctx);

/**
 * @brief Initialize BLAKE3 context (keyed mode)
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake3_init_keyed(
    nextssl_partial_hash_blake3_ctx_t *ctx,
    const uint8_t *key
);

/**
 * @brief Initialize BLAKE3 context (key derivation mode)
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake3_init_derive_key(
    nextssl_partial_hash_blake3_ctx_t *ctx,
    const char *context
);

NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake3_update(
    nextssl_partial_hash_blake3_ctx_t *ctx,
    const uint8_t *data,
    size_t data_len
);

/**
 * @brief Finalize and output fixed-length hash (32 bytes default)
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake3_final(
    nextssl_partial_hash_blake3_ctx_t *ctx,
    uint8_t *output
);

/**
 * @brief Finalize and output variable-length hash (extendable output)
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake3_finalize_xof(
    nextssl_partial_hash_blake3_ctx_t *ctx,
    uint8_t *output,
    size_t output_len
);

NEXTSSL_PARTIAL_API void
nextssl_partial_hash_blake3_destroy(nextssl_partial_hash_blake3_ctx_t *ctx);

NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake3(
    const uint8_t *data,
    size_t data_len,
    uint8_t *output
);

NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake3_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_HASH_BLAKE3_H */
