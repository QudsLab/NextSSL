/**
 * @file blake2b.h
 * @brief Layer 1 (Partial) - BLAKE2b Hash Function Interface
 * 
 * @visibility HIDDEN (NEXTSSL_PARTIAL_API)
 * @layer 1
 * @category hash
 * @subcategory blake2b
 * 
 * This interface provides BLAKE2b (64-bit optimized) hash function (RFC 7693).
 * BLAKE2b is faster than SHA-2/SHA-3 while providing equivalent security.
 * 
 * Security properties:
 * - Collision resistance (equivalent to SHA-3)
 * - Preimage resistance (equivalent to SHA-3)
 * - Faster than SHA-2/SHA-3 (optimized for 64-bit platforms)
 * - Built-in keyed hashing mode (MAC without HMAC construction)
 * - Variable output length (1 to 64 bytes)
 * - Built-in salt and personalization parameters
 * 
 * @warning BLAKE2 is NOT a drop-in replacement for SHA-2 (different output)
 * @warning For password hashing, use Argon2 (which uses BLAKE2 internally)
 * @warning Keyed mode provides MAC, but different from HMAC-BLAKE2b
 * 
 * Advantages over SHA-2:
 * - ~3x faster than SHA-256 on 64-bit platforms
 * - Built-in keyed mode (no HMAC needed)
 * - Variable output length (no truncation needed)
 * - Simpler implementation (fewer lines of code)
 * 
 * Thread safety: Each hash instance is NOT thread-safe.
 */

#ifndef NEXTSSL_PARTIAL_HASH_BLAKE2B_H
#define NEXTSSL_PARTIAL_HASH_BLAKE2B_H

#include <stddef.h>
#include <stdint.h>
#include "../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * BLAKE2b Types and Constants
 * ======================================================================== */

typedef struct nextssl_partial_hash_blake2b_ctx nextssl_partial_hash_blake2b_ctx_t;

#define NEXTSSL_BLAKE2B_BLOCKBYTES    128   /**< Block size */
#define NEXTSSL_BLAKE2B_OUTBYTES      64    /**< Maximum output size */
#define NEXTSSL_BLAKE2B_KEYBYTES      64    /**< Maximum key size */
#define NEXTSSL_BLAKE2B_SALTBYTES     16    /**< Salt size */
#define NEXTSSL_BLAKE2B_PERSONALBYTES 16    /**< Personalization size */

/* ========================================================================
 * BLAKE2b Lifecycle Functions
 * ======================================================================== */

/**
 * @brief Get required size for BLAKE2b context allocation
 */
NEXTSSL_PARTIAL_API size_t
nextssl_partial_hash_blake2b_ctx_size(void);

/**
 * @brief Initialize BLAKE2b context
 * 
 * @param ctx BLAKE2b context
 * @param output_len Desired output length (1 to 64 bytes)
 * @param key Optional key for MAC mode (NULL for hash mode)
 * @param key_len Length of key (0 if key is NULL, max 64 bytes)
 * @return 0 on success, negative error code on failure
 * 
 * @warning output_len MUST be 1-64 bytes
 * @warning key_len MUST be 0-64 bytes
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake2b_init(
    nextssl_partial_hash_blake2b_ctx_t *ctx,
    size_t output_len,
    const uint8_t *key,
    size_t key_len
);

/**
 * @brief Initialize BLAKE2b context with salt and personalization
 * 
 * @param ctx BLAKE2b context
 * @param output_len Desired output length (1 to 64 bytes)
 * @param key Optional key (NULL for hash mode)
 * @param key_len Length of key
 * @param salt Optional salt (NULL if not used)
 * @param personal Optional personalization (NULL if not used)
 * @return 0 on success, negative error code on failure
 * 
 * @warning salt MUST be 16 bytes if provided
 * @warning personal MUST be 16 bytes if provided
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake2b_init_full(
    nextssl_partial_hash_blake2b_ctx_t *ctx,
    size_t output_len,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *salt,
    const uint8_t *personal
);

NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake2b_update(
    nextssl_partial_hash_blake2b_ctx_t *ctx,
    const uint8_t *data,
    size_t data_len
);

NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake2b_final(
    nextssl_partial_hash_blake2b_ctx_t *ctx,
    uint8_t *output
);

NEXTSSL_PARTIAL_API void
nextssl_partial_hash_blake2b_destroy(nextssl_partial_hash_blake2b_ctx_t *ctx);

/* ========================================================================
 * BLAKE2b One-Shot Functions
 * ======================================================================== */

/**
 * @brief Compute BLAKE2b hash in one shot
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake2b(
    const uint8_t *data,
    size_t data_len,
    uint8_t *output,
    size_t output_len
);

/**
 * @brief Compute BLAKE2b MAC in one shot
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake2b_mac(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *data,
    size_t data_len,
    uint8_t *output,
    size_t output_len
);

NEXTSSL_PARTIAL_API int
nextssl_partial_hash_blake2b_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_HASH_BLAKE2B_H */
