/**
 * @file drbg.h
 * @brief Layer 1 (Partial) - DRBG (Deterministic Random Bit Generator) Interface
 * 
 * @visibility HIDDEN (NEXTSSL_PARTIAL_API)
 * @layer 1
 * @category core
 * @subcategory drbg
 * 
 * This interface provides DRBG implementations following NIST SP 800-90A.
 * Supports CTR-DRBG (AES-256), HMAC-DRBG (SHA-256/SHA-512), and Hash-DRBG (SHA-256/SHA-512).
 * 
 * Security properties:
 * - Prediction resistance (when reseeded regularly)
 * - Backtracking resistance (cannot determine past outputs from current state)
 * - Forward secrecy (state updates prevent rewinding)
 * - Must be seeded with at least 256 bits of entropy
 * 
 * @warning DRBG instances MUST be reseeded after generating 2^20 blocks or 2^48 bytes
 * @warning Never use weak entropy sources - always use cryptographically secure sources
 * @warning DRBG state MUST be securely wiped on destruction
 * 
 * NIST SP 800-90A Compliance:
 * - CTR-DRBG uses AES-256 with derivation function
 * - HMAC-DRBG uses SHA-256 or SHA-512
 * - Hash-DRBG uses SHA-256 or SHA-512
 * - All implementations support prediction resistance
 * - All implementations support personalization strings and additional input
 * 
 * Thread safety: Each DRBG instance is NOT thread-safe internally.
 * Multiple threads MUST use separate instances or external synchronization.
 */

#ifndef NEXTSSL_PARTIAL_CORE_DRBG_H
#define NEXTSSL_PARTIAL_CORE_DRBG_H

#include <stddef.h>
#include <stdint.h>
#include "../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * DRBG Types and Constants
 * ======================================================================== */

/**
 * @brief Opaque DRBG context structure
 * 
 * Internal state:
 * - CTR-DRBG: AES-256 key (256 bits) + V counter (128 bits)
 * - HMAC-DRBG: K value (256/512 bits) + V value (256/512 bits)
 * - Hash-DRBG: Seed material (440/888 bits) + C constant
 * 
 * Additional state:
 * - Reseed counter (tracks when reseeding is required)
 * - Security strength indicator
 */
typedef struct nextssl_partial_core_drbg_ctx nextssl_partial_core_drbg_ctx_t;

/**
 * @brief DRBG algorithm types
 */
typedef enum {
    NEXTSSL_DRBG_CTR_AES256,      /**< CTR-DRBG with AES-256 (NIST approved) */
    NEXTSSL_DRBG_HMAC_SHA256,     /**< HMAC-DRBG with SHA-256 (NIST approved) */
    NEXTSSL_DRBG_HMAC_SHA512,     /**< HMAC-DRBG with SHA-512 (NIST approved) */
    NEXTSSL_DRBG_HASH_SHA256,     /**< Hash-DRBG with SHA-256 (NIST approved) */
    NEXTSSL_DRBG_HASH_SHA512      /**< Hash-DRBG with SHA-512 (NIST approved) */
} nextssl_drbg_algorithm_t;

/**
 * @brief DRBG configuration flags
 */
typedef enum {
    NEXTSSL_DRBG_FLAG_NONE = 0,
    NEXTSSL_DRBG_FLAG_PREDICTION_RESISTANCE = (1 << 0),  /**< Force reseed on every generate */
    NEXTSSL_DRBG_FLAG_USE_DERIVATION = (1 << 1)          /**< Use derivation function (CTR-DRBG) */
} nextssl_drbg_flags_t;

/* NIST SP 800-90A limits */
#define NEXTSSL_DRBG_MAX_BYTES_PER_REQUEST    65536    /**< 2^16 bytes max per request */
#define NEXTSSL_DRBG_RESEED_INTERVAL          1048576  /**< 2^20 requests before reseed */
#define NEXTSSL_DRBG_MAX_PERSONALIZATION_LEN  256      /**< Max personalization string length */
#define NEXTSSL_DRBG_MAX_ADDITIONAL_INPUT_LEN 256      /**< Max additional input length */

/* ========================================================================
 * DRBG Lifecycle Functions
 * ======================================================================== */

/**
 * @brief Get required size for DRBG context allocation
 * 
 * @param algorithm DRBG algorithm type
 * @return Size in bytes needed for context, or 0 if algorithm invalid
 * 
 * @note Always call this before allocating context memory
 */
NEXTSSL_PARTIAL_API size_t
nextssl_partial_core_drbg_ctx_size(nextssl_drbg_algorithm_t algorithm);

/**
 * @brief Initialize DRBG instance
 * 
 * @param ctx DRBG context (must be pre-allocated)
 * @param algorithm DRBG algorithm type
 * @param entropy Entropy input (min 256 bits / 32 bytes)
 * @param entropy_len Length of entropy input
 * @param nonce Optional nonce (recommended: at least 128 bits)
 * @param nonce_len Length of nonce (0 if nonce is NULL)
 * @param personalization Optional personalization string
 * @param personalization_len Length of personalization (0 if NULL)
 * @param flags Configuration flags (prediction resistance, derivation)
 * @return 0 on success, negative error code on failure
 * 
 * @warning entropy_len MUST be >= 32 bytes (256 bits of entropy)
 * @warning nonce_len SHOULD be >= 16 bytes for proper security
 * @warning personalization_len MUST be <= NEXTSSL_DRBG_MAX_PERSONALIZATION_LEN
 * 
 * Security requirements:
 * - Entropy MUST come from cryptographically secure source
 * - Nonce SHOULD be unique for each instantiation
 * - Personalization string provides application-specific binding
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_drbg_init(
    nextssl_partial_core_drbg_ctx_t *ctx,
    nextssl_drbg_algorithm_t algorithm,
    const uint8_t *entropy,
    size_t entropy_len,
    const uint8_t *nonce,
    size_t nonce_len,
    const uint8_t *personalization,
    size_t personalization_len,
    uint32_t flags
);

/**
 * @brief Reseed DRBG instance with fresh entropy
 * 
 * @param ctx DRBG context
 * @param entropy Fresh entropy input (min 256 bits)
 * @param entropy_len Length of entropy input
 * @param additional Optional additional input
 * @param additional_len Length of additional input (0 if NULL)
 * @return 0 on success, negative error code on failure
 * 
 * @warning entropy_len MUST be >= 32 bytes
 * @warning additional_len MUST be <= NEXTSSL_DRBG_MAX_ADDITIONAL_INPUT_LEN
 * 
 * When to reseed:
 * - After 2^20 generate calls (NEXTSSL_DRBG_RESEED_INTERVAL)
 * - When entropy source has been compromised
 * - When prediction resistance is required
 * - After extended periods of inactivity
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_drbg_reseed(
    nextssl_partial_core_drbg_ctx_t *ctx,
    const uint8_t *entropy,
    size_t entropy_len,
    const uint8_t *additional,
    size_t additional_len
);

/**
 * @brief Generate random bytes from DRBG
 * 
 * @param ctx DRBG context
 * @param output Output buffer for random bytes
 * @param output_len Number of bytes to generate (max 65536)
 * @param additional Optional additional input (provides extra conditioning)
 * @param additional_len Length of additional input (0 if NULL)
 * @return 0 on success, negative error code on failure
 * 
 * @warning output_len MUST be <= NEXTSSL_DRBG_MAX_BYTES_PER_REQUEST
 * @warning additional_len MUST be <= NEXTSSL_DRBG_MAX_ADDITIONAL_INPUT_LEN
 * 
 * Error conditions:
 * - Returns error if reseed required (reseed counter exceeded)
 * - Returns error if output_len exceeds limits
 * - Returns error if context is invalid
 * 
 * Prediction resistance:
 * If NEXTSSL_DRBG_FLAG_PREDICTION_RESISTANCE is set, DRBG reseeds
 * automatically before generation (requires entropy callback).
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_drbg_generate(
    nextssl_partial_core_drbg_ctx_t *ctx,
    uint8_t *output,
    size_t output_len,
    const uint8_t *additional,
    size_t additional_len
);

/**
 * @brief Uninstantiate DRBG and securely wipe state
 * 
 * @param ctx DRBG context to destroy
 * 
 * @note This function MUST be called to prevent state leakage
 * @note Performs secure memory wiping of all internal state
 * @note Safe to call on already-destroyed or NULL contexts
 */
NEXTSSL_PARTIAL_API void
nextssl_partial_core_drbg_destroy(nextssl_partial_core_drbg_ctx_t *ctx);

/* ========================================================================
 * DRBG Utility Functions
 * ======================================================================== */

/**
 * @brief Check if DRBG requires reseeding
 * 
 * @param ctx DRBG context
 * @return 1 if reseed required, 0 if not, negative on error
 * 
 * @note Checks reseed counter against NEXTSSL_DRBG_RESEED_INTERVAL
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_drbg_needs_reseed(const nextssl_partial_core_drbg_ctx_t *ctx);

/**
 * @brief Get current reseed counter value
 * 
 * @param ctx DRBG context
 * @return Current reseed counter value, or 0 on error
 * 
 * @note Useful for monitoring DRBG health
 */
NEXTSSL_PARTIAL_API uint64_t
nextssl_partial_core_drbg_reseed_counter(const nextssl_partial_core_drbg_ctx_t *ctx);

/**
 * @brief Self-test DRBG implementation against NIST test vectors
 * 
 * @param algorithm DRBG algorithm to test
 * @return 0 if all tests pass, negative error code on failure
 * 
 * @note Runs NIST CAVP test vectors for selected algorithm
 * @note Should be run during library initialization or on-demand
 * @note Does NOT require external entropy (uses fixed test vectors)
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_drbg_selftest(nextssl_drbg_algorithm_t algorithm);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_CORE_DRBG_H */

/**
 * Implementation Notes:
 * 
 * 1. CTR-DRBG Implementation:
 *    - Uses AES-256 in counter mode
 *    - Key K: 256 bits, V counter: 128 bits
 *    - Update function: BCC-based derivation or simple concatenation
 *    - State update after every generate
 * 
 * 2. HMAC-DRBG Implementation:
 *    - Uses HMAC-SHA-256 or HMAC-SHA-512
 *    - State: K (key), V (value)
 *    - Update function: HMAC(K, V || 0x00 || provided_data)
 *    - Simpler and faster than CTR-DRBG
 * 
 * 3. Hash-DRBG Implementation:
 *    - Uses SHA-256 or SHA-512
 *    - State: seed_material, C constant
 *    - Generate function: iterative hashing
 *    - Requires larger state than HMAC-DRBG
 * 
 * 4. Reseed Counter:
 *    - Incremented on every generate() call
 *    - When counter >= NEXTSSL_DRBG_RESEED_INTERVAL, reseed required
 *    - Reset to 1 after reseeding
 * 
 * 5. Memory Management:
 *    - Context structures are opaque (defined in .c file)
 *    - Caller responsible for allocation (use nextssl_partial_core_drbg_ctx_size)
 *    - destroy() wipes memory securely
 * 
 * 6. Thread Safety:
 *    - NOT thread-safe by design (performance)
 *    - Each thread should have separate DRBG instance
 *    - Or use external locking around DRBG calls
 * 
 * SECURITY AUDIT NOTES:
 * - [ ] Verify proper entropy requirements (>= 256 bits)
 * - [ ] Check reseed counter enforcement
 * - [ ] Validate secure memory wiping in destroy()
 * - [ ] Test NIST test vectors compliance
 * - [ ] Review state update functions for proper forward secrecy
 * - [ ] Verify prediction resistance implementation
 * - [ ] Check limits enforcement (max bytes per request, etc.)
 */
