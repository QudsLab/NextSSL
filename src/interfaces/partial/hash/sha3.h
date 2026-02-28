/**
 * @file sha3.h
 * @brief Layer 1 (Partial) - SHA-3 Family Hash Functions Interface
 * 
 * @visibility HIDDEN (NEXTSSL_PARTIAL_API)
 * @layer 1
 * @category hash
 * @subcategory sha3
 * 
 * This interface provides SHA-3 family hash functions (NIST FIPS 202).
 * Supports SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, and SHAKE256.
 * 
 * SHA-3 is based on the Keccak sponge construction, fundamentally different from SHA-2.
 * 
 * Security properties:
 * - Collision resistance (same as SHA-2)
 * - Preimage resistance (same as SHA-2)
 * - Second preimage resistance (same as SHA-2)
 * - Resistance to length extension attacks (unlike SHA-2)
 * - Based on sponge construction (different from Merkle-Damgård)
 * 
 * @warning Not a replacement for SHA-2 (both are secure)
 * @warning SHA-3 is generally slower than SHA-2 (without hardware acceleration)
 * @warning SHAKE is XOF (extendable-output function), not fixed-length hash
 * 
 * Use cases:
 * - When length extension resistance is required
 * - Cryptographic diversity (different design from SHA-2)
 * - Post-quantum hash-based signatures (SPHINCS+)
 * - Random number generation (SHAKE)
 * 
 * Thread safety: Each hash instance is NOT thread-safe.
 * Multiple threads MUST use separate instances or external synchronization.
 */

#ifndef NEXTSSL_PARTIAL_HASH_SHA3_H
#define NEXTSSL_PARTIAL_HASH_SHA3_H

#include <stddef.h>
#include <stdint.h>
#include "../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * SHA-3 Types and Constants
 * ======================================================================== */

/**
 * @brief Opaque SHA-3 context structure
 * 
 * Internal state:
 * - Keccak state (1600-bit / 200-byte state array)
 * - Rate (number of bytes absorbed per permutation)
 * - Capacity (security parameter)
 * - Algorithm identifier
 * - Absorb/squeeze phase indicator
 */
typedef struct nextssl_partial_hash_sha3_ctx nextssl_partial_hash_sha3_ctx_t;

/**
 * @brief SHA-3 algorithm types
 */
typedef enum {
    NEXTSSL_SHA3_224,       /**< SHA3-224 (28-byte fixed output) */
    NEXTSSL_SHA3_256,       /**< SHA3-256 (32-byte fixed output) */
    NEXTSSL_SHA3_384,       /**< SHA3-384 (48-byte fixed output) */
    NEXTSSL_SHA3_512,       /**< SHA3-512 (64-byte fixed output) */
    NEXTSSL_SHAKE128,       /**< SHAKE128 (extendable output, 128-bit security) */
    NEXTSSL_SHAKE256        /**< SHAKE256 (extendable output, 256-bit security) */
} nextssl_sha3_algorithm_t;

/* SHA-3 fixed output sizes */
#define NEXTSSL_SHA3_224_SIZE      28    /**< SHA3-224 output size in bytes */
#define NEXTSSL_SHA3_256_SIZE      32    /**< SHA3-256 output size in bytes */
#define NEXTSSL_SHA3_384_SIZE      48    /**< SHA3-384 output size in bytes */
#define NEXTSSL_SHA3_512_SIZE      64    /**< SHA3-512 output size in bytes */
#define NEXTSSL_SHA3_MAX_SIZE      64    /**< Maximum SHA3 fixed output size */

/* Keccak state size */
#define NEXTSSL_KECCAK_STATE_SIZE  200   /**< Keccak state size (1600 bits) */

/* ========================================================================
 * SHA-3 Lifecycle Functions (Fixed-Output)
 * ======================================================================== */

/**
 * @brief Get required size for SHA-3 context allocation
 * 
 * @param algorithm SHA-3 algorithm type
 * @return Size in bytes needed for context, or 0 if algorithm invalid
 * 
 * @note Always call this before allocating context memory
 */
NEXTSSL_PARTIAL_API size_t
nextssl_partial_hash_sha3_ctx_size(nextssl_sha3_algorithm_t algorithm);

/**
 * @brief Initialize SHA-3 context
 * 
 * @param ctx SHA-3 context (must be pre-allocated)
 * @param algorithm SHA-3 algorithm type
 * @return 0 on success, negative error code on failure
 * 
 * Initializes Keccak sponge state to zeros and sets rate/capacity.
 * 
 * Rate/Capacity pairs:
 * - SHA3-224: rate=144, capacity=456
 * - SHA3-256: rate=136, capacity=464
 * - SHA3-384: rate=104, capacity=496
 * - SHA3-512: rate=72, capacity=528
 * - SHAKE128: rate=168, capacity=256
 * - SHAKE256: rate=136, capacity=464
 * 
 * @note Must be called before first update
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_sha3_init(
    nextssl_partial_hash_sha3_ctx_t *ctx,
    nextssl_sha3_algorithm_t algorithm
);

/**
 * @brief Update SHA-3 hash with data (absorb phase)
 * 
 * @param ctx SHA-3 context
 * @param data Input data to hash
 * @param data_len Length of input data in bytes
 * @return 0 on success, negative error code on failure
 * 
 * @note Can be called multiple times to absorb data in chunks
 * @note Order of update calls MUST match data structure
 * @note For SHAKE, this is the absorb phase
 * 
 * Example usage:
 * ```c
 * nextssl_partial_hash_sha3_init(&ctx, NEXTSSL_SHA3_256);
 * nextssl_partial_hash_sha3_update(&ctx, chunk1, len1);
 * nextssl_partial_hash_sha3_update(&ctx, chunk2, len2);
 * nextssl_partial_hash_sha3_final(&ctx, hash);
 * ```
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_sha3_update(
    nextssl_partial_hash_sha3_ctx_t *ctx,
    const uint8_t *data,
    size_t data_len
);

/**
 * @brief Finalize SHA-3 hash and output digest (squeeze phase)
 * 
 * @param ctx SHA-3 context
 * @param output Output buffer for hash digest
 * @return 0 on success, negative error code on failure
 * 
 * @warning output buffer MUST be at least NEXTSSL_SHA3_*_SIZE bytes
 * @warning For fixed-output SHA3 (not SHAKE), output length is fixed
 * @warning For SHAKE, use shake_squeeze() instead
 * @warning After final(), context is reset and can be reinitialized
 * 
 * Output sizes:
 * - SHA3-224: 28 bytes
 * - SHA3-256: 32 bytes
 * - SHA3-384: 48 bytes
 * - SHA3-512: 64 bytes
 * 
 * @note For SHAKE, this is equivalent to shake_squeeze() with fixed length
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_sha3_final(
    nextssl_partial_hash_sha3_ctx_t *ctx,
    uint8_t *output
);

/**
 * @brief Reset SHA-3 context for reuse with same algorithm
 * 
 * @param ctx SHA-3 context
 * @return 0 on success, negative error code on failure
 * 
 * @note Resets Keccak state to zeros (same as init)
 * @note More efficient than destroy + init
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_sha3_reset(nextssl_partial_hash_sha3_ctx_t *ctx);

/**
 * @brief Destroy SHA-3 context and wipe state
 * 
 * @param ctx SHA-3 context to destroy
 * 
 * @note Wipes Keccak state from memory
 * @note Safe to call on already-destroyed or NULL contexts
 */
NEXTSSL_PARTIAL_API void
nextssl_partial_hash_sha3_destroy(nextssl_partial_hash_sha3_ctx_t *ctx);

/* ========================================================================
 * SHAKE (Extendable-Output Functions)
 * ======================================================================== */

/**
 * @brief Finalize SHAKE and squeeze arbitrary-length output
 * 
 * @param ctx SHA-3 context (must be initialized with SHAKE128 or SHAKE256)
 * @param output Output buffer for squeezed data
 * @param output_len Desired output length (arbitrary)
 * @return 0 on success, negative error code on failure
 * 
 * @warning output_len can be ANY size (not limited like fixed-output SHA3)
 * @warning For SHAKE128, security level is min(output_len, 128 bits)
 * @warning For SHAKE256, security level is min(output_len, 256 bits)
 * 
 * @note Can be called multiple times to squeeze more output
 * @note Each call continues squeezing from where previous call left off
 * 
 * Example (generating 128 bytes from SHAKE256):
 * ```c
 * nextssl_partial_hash_sha3_init(&ctx, NEXTSSL_SHAKE256);
 * nextssl_partial_hash_sha3_update(&ctx, input, input_len);
 * 
 * uint8_t output[128];
 * nextssl_partial_hash_sha3_shake_squeeze(&ctx, output, 128);
 * 
 * // Can squeeze more if needed
 * uint8_t more[64];
 * nextssl_partial_hash_sha3_shake_squeeze(&ctx, more, 64);
 * ```
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_sha3_shake_squeeze(
    nextssl_partial_hash_sha3_ctx_t *ctx,
    uint8_t *output,
    size_t output_len
);

/* ========================================================================
 * SHA-3 One-Shot Functions
 * ======================================================================== */

/**
 * @brief Compute SHA-3 hash in one shot (non-streaming)
 * 
 * @param algorithm SHA-3 algorithm type (NOT SHAKE)
 * @param data Input data to hash
 * @param data_len Length of input data
 * @param output Output buffer for hash digest
 * @return 0 on success, negative error code on failure
 * 
 * @warning output buffer MUST be at least NEXTSSL_SHA3_*_SIZE bytes
 * @warning For SHAKE, use shake_one_shot() instead
 * 
 * Example:
 * ```c
 * uint8_t hash[32];
 * nextssl_partial_hash_sha3(NEXTSSL_SHA3_256, data, len, hash);
 * ```
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_sha3(
    nextssl_sha3_algorithm_t algorithm,
    const uint8_t *data,
    size_t data_len,
    uint8_t *output
);

/**
 * @brief Compute SHAKE output in one shot
 * 
 * @param algorithm SHAKE algorithm (SHAKE128 or SHAKE256)
 * @param data Input data to absorb
 * @param data_len Length of input data
 * @param output Output buffer for squeezed data
 * @param output_len Desired output length (arbitrary)
 * @return 0 on success, negative error code on failure
 * 
 * Example (SHAKE128 generating 64 bytes):
 * ```c
 * uint8_t output[64];
 * nextssl_partial_hash_sha3_shake(NEXTSSL_SHAKE128, data, len, output, 64);
 * ```
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_sha3_shake(
    nextssl_sha3_algorithm_t algorithm,
    const uint8_t *data,
    size_t data_len,
    uint8_t *output,
    size_t output_len
);

/* ========================================================================
 * SHA-3 Utility Functions
 * ======================================================================== */

/**
 * @brief Get SHA-3 output size for algorithm
 * 
 * @param algorithm SHA-3 algorithm type
 * @return Output size in bytes, or 0 if variable (SHAKE) or invalid
 * 
 * @note Returns 0 for SHAKE (extendable output)
 */
NEXTSSL_PARTIAL_API size_t
nextssl_partial_hash_sha3_output_size(nextssl_sha3_algorithm_t algorithm);

/**
 * @brief Get SHA-3 rate (absorption capacity) for algorithm
 * 
 * @param algorithm SHA-3 algorithm type
 * @return Rate in bytes, or 0 if algorithm invalid
 * 
 * Rates:
 * - SHA3-224: 144 bytes
 * - SHA3-256: 136 bytes
 * - SHA3-384: 104 bytes
 * - SHA3-512: 72 bytes
 * - SHAKE128: 168 bytes
 * - SHAKE256: 136 bytes
 */
NEXTSSL_PARTIAL_API size_t
nextssl_partial_hash_sha3_rate(nextssl_sha3_algorithm_t algorithm);

/**
 * @brief Self-test SHA-3 implementation against NIST test vectors
 * 
 * @param algorithm SHA-3 algorithm to test
 * @return 0 if all tests pass, negative error code on failure
 * 
 * @note Runs NIST FIPS 202 test vectors
 * @note Should be run during library initialization
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_hash_sha3_selftest(nextssl_sha3_algorithm_t algorithm);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_HASH_SHA3_H */

/**
 * Implementation Notes:
 * 
 * 1. Keccak Sponge Construction:
 *    - State: 1600-bit array (5x5x64 bits)
 *    - Rate (r): Amount absorbed/squeezed per iteration
 *    - Capacity (c): Security parameter (c = 1600 - r)
 *    - Security level: c/2 bits (e.g., 256-bit capacity -> 128-bit security)
 * 
 * 2. Keccak-f[1600] Permutation:
 *    - 24 rounds
 *    - Operations: θ (theta), ρ (rho), π (pi), χ (chi), ι (iota)
 *    - Operates on 5x5 array of 64-bit lanes
 *    - Highly parallelizable
 * 
 * 3. SHA-3 Padding (different from SHA-2):
 *    - Append '10*1' (bit '1', zero or more '0's, bit '1')
 *    - Padding ensures last block is exactly rate bytes
 *    - Domain separation: 0x06 for SHA3, 0x1F for SHAKE
 * 
 * 4. Rate/Capacity Tradeoff:
 *    - Larger rate: faster (more data per permutation)
 *    - Larger capacity: more secure (higher security level)
 *    - SHA3-512: smallest rate (72 bytes) but highest capacity (528 bytes)
 *    - SHAKE128: largest rate (168 bytes) but smallest capacity (256 bytes)
 * 
 * 5. SHAKE (Extendable-Output Functions):
 *    - Can produce arbitrary-length output
 *    - Absorb phase: input data (like regular hash)
 *    - Squeeze phase: output arbitrary-length data
 *    - Can squeeze multiple times (each squeeze continues from previous state)
 *    - Use case: key derivation, random number generation, padding
 * 
 * 6. Performance (typical x64 CPU, no hardware acceleration):
 *    - SHA3-256: ~150 MB/s (slower than SHA-256's 300 MB/s)
 *    - SHAKE128: ~200 MB/s (faster rate)
 *    - With future hardware acceleration, SHA-3 could be faster
 * 
 * 7. Security Status (2024):
 *    - All SHA-3 variants: Secure, no practical attacks
 *    - Larger security margin than SHA-2 (24 rounds vs 64/80 rounds)
 *    - Resistant to length extension attacks (unlike SHA-2)
 *    - Post-quantum secure (no known quantum attacks)
 * 
 * 8. SHA-3 vs SHA-2:
 *    - Different design (sponge vs Merkle-Damgård)
 *    - SHA-3 slower without hardware acceleration
 *    - SHA-3 has length extension resistance
 *    - Both are secure, not incompatible
 *    - Use SHA-2 for compatibility, SHA-3 for diversity
 * 
 * 9. Use Cases by Variant:
 *    - SHA3-256: General purpose, same security as SHA-256
 *    - SHA3-512: High security applications
 *    - SHAKE128: Fast hashing with variable output
 *    - SHAKE256: High-security variable-length output
 * 
 * SECURITY AUDIT NOTES:
 * - [ ] Verify Keccak-f[1600] permutation correctness (24 rounds)
 * - [ ] Check padding implementation (0x06 for SHA3, 0x1F for SHAKE)
 * - [ ] Validate rate/capacity parameters for each variant
 * - [ ] Test NIST FIPS 202 test vectors (all variants)
 * - [ ] Verify state initialization (zeros)
 * - [ ] Check secure state wiping in destroy()
 * - [ ] Ensure SHAKE squeeze phase correctness
 */
