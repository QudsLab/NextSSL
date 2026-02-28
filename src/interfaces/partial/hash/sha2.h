/**
 * @file sha2.h
 * @brief Layer 1 (Partial) - SHA-2 Family Hash Functions Interface
 * 
 * @visibility HIDDEN (NEXTSSL_PARTIAL_API)
 * @layer 1
 * @category hash
 * @subcategory sha2
 * 
 * This interface provides SHA-2 family hash functions (NIST FIPS 180-4).
 * Supports SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256.
 * 
 * Security properties:
 * - Collision resistance (infeasible to find two inputs with same hash)
 * - Preimage resistance (infeasible to find input from hash)
 * - Second preimage resistance (infeasible to find different input with same hash)
 * - Avalanche effect (small input change causes large hash change)
 * 
 * @warning SHA-1 is NOT included (cryptographically broken since 2017)
 * @warning For new applications, consider BLAKE2/BLAKE3 (faster)
 * @warning SHA-256/512 are still secure and widely standardized
 * 
 * Use cases:
 * - Digital signatures (SHA-256, SHA-512)
 * - Certificate fingerprints
 * - Password hashing base (with PBKDF2/Argon2)
 * - File integrity verification
 * - Blockchain/cryptocurrency
 * 
 * Thread safety: Each hash instance is NOT thread-safe.
 * Multiple threads MUST use separate instances or external synchronization.
 */

#ifndef NEXTSSL_PARTIAL_HASH_SHA2_H
#define NEXTSSL_PARTIAL_HASH_SHA2_H

#include <stddef.h>
#include <stdint.h>
#include "interfaces/visibility.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * SHA-2 Types and Constants
 * ======================================================================== */

/**
 * @brief Opaque SHA-2 context structure
 * 
 * Internal state:
 * - Hash state (8x 32-bit or 64-bit words)
 * - Message buffer (64 or 128 bytes)
 * - Bit count (message length tracking)
 * - Algorithm identifier
 */
typedef struct nextssl_partial_hash_sha2_ctx nextssl_partial_hash_sha2_ctx_t;

/**
 * @brief SHA-2 algorithm types
 */
typedef enum {
    NEXTSSL_SHA224,         /**< SHA-224 (28-byte output, 32-bit words) */
    NEXTSSL_SHA256,         /**< SHA-256 (32-byte output, 32-bit words) */
    NEXTSSL_SHA384,         /**< SHA-384 (48-byte output, 64-bit words) */
    NEXTSSL_SHA512,         /**< SHA-512 (64-byte output, 64-bit words) */
    NEXTSSL_SHA512_224,     /**< SHA-512/224 (28-byte output, 64-bit words) */
    NEXTSSL_SHA512_256      /**< SHA-512/256 (32-byte output, 64-bit words) */
} nextssl_sha2_algorithm_t;

/* SHA-2 output sizes */
#define NEXTSSL_SHA224_SIZE        28    /**< SHA-224 output size in bytes */
#define NEXTSSL_SHA256_SIZE        32    /**< SHA-256 output size in bytes */
#define NEXTSSL_SHA384_SIZE        48    /**< SHA-384 output size in bytes */
#define NEXTSSL_SHA512_SIZE        64    /**< SHA-512 output size in bytes */
#define NEXTSSL_SHA512_224_SIZE    28    /**< SHA-512/224 output size */
#define NEXTSSL_SHA512_256_SIZE    32    /**< SHA-512/256 output size */
#define NEXTSSL_SHA2_MAX_SIZE      64    /**< Maximum SHA-2 output size */

/* SHA-2 block sizes (internal) */
#define NEXTSSL_SHA256_BLOCK_SIZE  64    /**< SHA-256 block size (512 bits) */
#define NEXTSSL_SHA512_BLOCK_SIZE  128   /**< SHA-512 block size (1024 bits) */

/* ========================================================================
 * SHA-2 Lifecycle Functions
 * ======================================================================== */

/**
 * @brief Get required size for SHA-2 context allocation
 * 
 * @param algorithm SHA-2 algorithm type
 * @return Size in bytes needed for context, or 0 if algorithm invalid
 * 
 * @note Always call this before allocating context memory
 */
NEXTSSL_PARTIAL_API size_t
nextssl_partial_hash_sha2_ctx_size(nextssl_sha2_algorithm_t algorithm);

/**
 * @brief Initialize SHA-2 context
 * 
 * @param ctx SHA-2 context (must be pre-allocated)
 * @param algorithm SHA-2 algorithm type
 * @return 0 on success, negative error code on failure
 * 
 * Initializes internal state with algorithm-specific IV (initial values).
 * 
 * @note Must be called before first update
 * @note Can be called again to reset context for reuse
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_sha2_init(
    nextssl_partial_hash_sha2_ctx_t *ctx,
    nextssl_sha2_algorithm_t algorithm
);

/**
 * @brief Update SHA-2 hash with data (streaming)
 * 
 * @param ctx SHA-2 context
 * @param data Input data to hash
 * @param data_len Length of input data in bytes
 * @return 0 on success, negative error code on failure
 * 
 * @note Can be called multiple times to process data in chunks
 * @note Order of update calls MUST match data structure
 * 
 * Example usage (streaming):
 * ```c
 * nextssl_partial_hash_sha2_init(&ctx, NEXTSSL_SHA256);
 * nextssl_partial_hash_sha2_update(&ctx, chunk1, len1);
 * nextssl_partial_hash_sha2_update(&ctx, chunk2, len2);
 * nextssl_partial_hash_sha2_final(&ctx, hash);
 * ```
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_sha2_update(
    nextssl_partial_hash_sha2_ctx_t *ctx,
    const uint8_t *data,
    size_t data_len
);

/**
 * @brief Finalize SHA-2 hash and output digest
 * 
 * @param ctx SHA-2 context
 * @param output Output buffer for hash digest
 * @return 0 on success, negative error code on failure
 * 
 * @warning output buffer MUST be at least NEXTSSL_SHA*_SIZE bytes
 * @warning After final(), context is reset and can be reinitialized
 * 
 * Output sizes:
 * - SHA-224: 28 bytes
 * - SHA-256: 32 bytes
 * - SHA-384: 48 bytes
 * - SHA-512: 64 bytes
 * - SHA-512/224: 28 bytes
 * - SHA-512/256: 32 bytes
 * 
 * @note Context state is wiped after finalization
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_sha2_final(
    nextssl_partial_hash_sha2_ctx_t *ctx,
    uint8_t *output
);

/**
 * @brief Reset SHA-2 context for reuse with same algorithm
 * 
 * @param ctx SHA-2 context
 * @return 0 on success, negative error code on failure
 * 
 * @note Resets to initial state (same as init)
 * @note More efficient than destroy + init
 * 
 * Use case: Hashing multiple messages with same algorithm
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_sha2_reset(nextssl_partial_hash_sha2_ctx_t *ctx);

/**
 * @brief Destroy SHA-2 context and wipe state
 * 
 * @param ctx SHA-2 context to destroy
 * 
 * @note Wipes internal state from memory
 * @note Safe to call on already-destroyed or NULL contexts
 */
NEXTSSL_PARTIAL_API void
nextssl_partial_hash_sha2_destroy(nextssl_partial_hash_sha2_ctx_t *ctx);

/* ========================================================================
 * SHA-2 One-Shot Functions
 * ======================================================================== */

/**
 * @brief Compute SHA-2 hash in one shot (non-streaming)
 * 
 * @param algorithm SHA-2 algorithm type
 * @param data Input data to hash
 * @param data_len Length of input data
 * @param output Output buffer for hash digest
 * @return 0 on success, negative error code on failure
 * 
 * @warning output buffer MUST be at least NEXTSSL_SHA*_SIZE bytes
 * 
 * @note This is a convenience function equivalent to init + update + final
 * @note More efficient than streaming API for small messages
 * 
 * Example:
 * ```c
 * uint8_t hash[32];
 * nextssl_partial_hash_sha2(NEXTSSL_SHA256, data, len, hash);
 * ```
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_sha2(
    nextssl_sha2_algorithm_t algorithm,
    const uint8_t *data,
    size_t data_len,
    uint8_t *output
);

/* ========================================================================
 * SHA-2 Utility Functions
 * ======================================================================== */

/**
 * @brief Get SHA-2 output size for algorithm
 * 
 * @param algorithm SHA-2 algorithm type
 * @return Output size in bytes, or 0 if algorithm invalid
 * 
 * Output sizes:
 * - SHA-224: 28 bytes
 * - SHA-256: 32 bytes
 * - SHA-384: 48 bytes
 * - SHA-512: 64 bytes
 * - SHA-512/224: 28 bytes
 * - SHA-512/256: 32 bytes
 */
NEXTSSL_PARTIAL_API size_t
nextssl_partial_hash_sha2_output_size(nextssl_sha2_algorithm_t algorithm);

/**
 * @brief Get SHA-2 block size for algorithm
 * 
 * @param algorithm SHA-2 algorithm type
 * @return Block size in bytes, or 0 if algorithm invalid
 * 
 * @note Block size is the internal processing block size
 * @note SHA-224/256: 64 bytes (512 bits)
 * @note SHA-384/512/512-224/512-256: 128 bytes (1024 bits)
 */
NEXTSSL_PARTIAL_API size_t
nextssl_partial_hash_sha2_block_size(nextssl_sha2_algorithm_t algorithm);

/**
 * @brief Self-test SHA-2 implementation against NIST test vectors
 * 
 * @param algorithm SHA-2 algorithm to test
 * @return 0 if all tests pass, negative error code on failure
 * 
 * @note Runs NIST FIPS 180-4 test vectors
 * @note Should be run during library initialization
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_sha2_selftest(nextssl_sha2_algorithm_t algorithm);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_HASH_SHA2_H */

/**
 * Implementation Notes:
 * 
 * 1. SHA-256 Family (32-bit words, 64-byte blocks):
 *    - SHA-224: Truncated SHA-256 (different IV)
 *    - SHA-256: Standard 256-bit hash
 *    - Block size: 512 bits (64 bytes)
 *    - Rounds: 64
 *    - Operations: Ch, Maj, Σ0, Σ1, σ0, σ1
 * 
 * 2. SHA-512 Family (64-bit words, 128-byte blocks):
 *    - SHA-384: Truncated SHA-512 (different IV)
 *    - SHA-512: Standard 512-bit hash
 *    - SHA-512/224: Truncated to 224 bits (different IV)
 *    - SHA-512/256: Truncated to 256 bits (different IV)
 *    - Block size: 1024 bits (128 bytes)
 *    - Rounds: 80
 *    - Operations: Similar to SHA-256 but 64-bit
 * 
 * 3. Padding (NIST FIPS 180-4):
 *    - Append bit '1'
 *    - Append zero bits until len ≡ 448 (mod 512) or 896 (mod 1024)
 *    - Append 64-bit (SHA-256) or 128-bit (SHA-512) message length
 * 
 * 4. Context Structure:
 *    - SHA-256: 8x 32-bit state, 64-byte buffer, 64-bit counter
 *    - SHA-512: 8x 64-bit state, 128-byte buffer, 128-bit counter
 * 
 * 5. Performance (typical x64 CPU):
 *    - SHA-256: ~300 MB/s (scalar), ~900 MB/s (with SHA-NI)
 *    - SHA-512: ~500 MB/s (scalar, benefits from 64-bit operations)
 *    - BLAKE2/BLAKE3 are faster for same security level
 * 
 * 6. Security Status (2024):
 *    - SHA-256: Secure, no practical attacks
 *    - SHA-512: Secure, no practical attacks
 *    - SHA-224/384: Secure (truncated versions)
 *    - SHA-512/224, SHA-512/256: Secure, less common
 *    - Birthday attack bound: 2^(n/2) for n-bit hash
 * 
 * 7. Hardware Acceleration:
 *    - Intel SHA Extensions (SHA-NI): SHA-256 acceleration
 *    - ARM Crypto Extensions: SHA-256 acceleration
 *    - No hardware acceleration for SHA-512 (yet)
 * 
 * 8. Use Cases by Variant:
 *    - SHA-256: Most widely used, default choice
 *    - SHA-512: When 256-bit security needed, or on 64-bit systems
 *    - SHA-384: Less common, but provides 192-bit security
 *    - SHA-224: Rarely used (truncated SHA-256)
 *    - SHA-512/256: Alternative to SHA-256 with faster SHA-512 on 64-bit
 * 
 * SECURITY AUDIT NOTES:
 * - [ ] Verify correct padding implementation (FIPS 180-4)
 * - [ ] Check endianness handling (big-endian for SHA-2)
 * - [ ] Validate initial values (IVs) for each variant
 * - [ ] Test NIST FIPS 180-4 test vectors (all variants)
 * - [ ] Verify message length tracking (64-bit or 128-bit)
 * - [ ] Check secure state wiping in destroy()
 * - [ ] Ensure no buffer overflows in update()
 */
