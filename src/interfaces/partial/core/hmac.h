/**
 * @file hmac.h
 * @brief Layer 1 (Partial) - HMAC (Hash-based Message Authentication Code) Interface
 * 
 * @visibility HIDDEN (NEXTSSL_PARTIAL_API)
 * @layer 1
 * @category core
 * @subcategory hmac
 * 
 * This interface provides HMAC implementations following RFC 2104.
 * Supports SHA-256, SHA-512, SHA3-256, SHA3-512, and BLAKE2b/BLAKE2s.
 * 
 * Security properties:
 * - Message authentication (integrity + authenticity)
 * - Pseudorandom function (PRF) property
 * - Resistance to length extension attacks (unlike plain hash)
 * - Key derivation suitable (but prefer HKDF for explicit KDF)
 * 
 * @warning Key length SHOULD be >= hash output size (32 bytes for SHA-256)
 * @warning Shorter keys reduce security; longer keys are hashed down
 * @warning Never reuse keys across different applications/protocols
 * 
 * RFC 2104 Compliance:
 * - HMAC(K, M) = H((K ⊕ opad) || H((K ⊕ ipad) || M))
 * - ipad = 0x36 repeated, opad = 0x5c repeated
 * - If key > block size, key = H(key)
 * - If key < block size, key is zero-padded
 * 
 * Thread safety: Each HMAC instance is NOT thread-safe.
 * Multiple threads MUST use separate instances or external synchronization.
 */

#ifndef NEXTSSL_PARTIAL_CORE_HMAC_H
#define NEXTSSL_PARTIAL_CORE_HMAC_H

#include <stddef.h>
#include <stdint.h>
#include "../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * HMAC Types and Constants
 * ======================================================================== */

/**
 * @brief Opaque HMAC context structure
 * 
 * Internal state:
 * - Hash algorithm context (for inner/outer hash)
 * - Processed key (K ⊕ ipad, K ⊕ opad)
 * - Current hash state
 */
typedef struct nextssl_partial_core_hmac_ctx nextssl_partial_core_hmac_ctx_t;

/**
 * @brief HMAC algorithm types
 */
typedef enum {
    NEXTSSL_HMAC_SHA256,      /**< HMAC-SHA-256 (32-byte output) */
    NEXTSSL_HMAC_SHA512,      /**< HMAC-SHA-512 (64-byte output) */
    NEXTSSL_HMAC_SHA3_256,    /**< HMAC-SHA3-256 (32-byte output) */
    NEXTSSL_HMAC_SHA3_512,    /**< HMAC-SHA3-512 (64-byte output) */
    NEXTSSL_HMAC_BLAKE2B,     /**< HMAC-BLAKE2b (64-byte output) */
    NEXTSSL_HMAC_BLAKE2S      /**< HMAC-BLAKE2s (32-byte output) */
} nextssl_hmac_algorithm_t;

/* HMAC output sizes */
#define NEXTSSL_HMAC_SHA256_SIZE    32   /**< SHA-256 output size in bytes */
#define NEXTSSL_HMAC_SHA512_SIZE    64   /**< SHA-512 output size in bytes */
#define NEXTSSL_HMAC_SHA3_256_SIZE  32   /**< SHA3-256 output size in bytes */
#define NEXTSSL_HMAC_SHA3_512_SIZE  64   /**< SHA3-512 output size in bytes */
#define NEXTSSL_HMAC_BLAKE2B_SIZE   64   /**< BLAKE2b output size in bytes */
#define NEXTSSL_HMAC_BLAKE2S_SIZE   32   /**< BLAKE2s output size in bytes */
#define NEXTSSL_HMAC_MAX_SIZE       64   /**< Maximum HMAC output size */

/* HMAC block sizes (for key processing) */
#define NEXTSSL_HMAC_SHA256_BLOCK_SIZE    64    /**< SHA-256 block size */
#define NEXTSSL_HMAC_SHA512_BLOCK_SIZE    128   /**< SHA-512 block size */
#define NEXTSSL_HMAC_SHA3_256_BLOCK_SIZE  136   /**< SHA3-256 block size (rate) */
#define NEXTSSL_HMAC_SHA3_512_BLOCK_SIZE  72    /**< SHA3-512 block size (rate) */
#define NEXTSSL_HMAC_BLAKE2B_BLOCK_SIZE   128   /**< BLAKE2b block size */
#define NEXTSSL_HMAC_BLAKE2S_BLOCK_SIZE   64    /**< BLAKE2s block size */

/* ========================================================================
 * HMAC Lifecycle Functions
 * ======================================================================== */

/**
 * @brief Get required size for HMAC context allocation
 * 
 * @param algorithm HMAC algorithm type
 * @return Size in bytes needed for context, or 0 if algorithm invalid
 * 
 * @note Always call this before allocating context memory
 */
NEXTSSL_PARTIAL_API size_t
nextssl_partial_core_hmac_ctx_size(nextssl_hmac_algorithm_t algorithm);

/**
 * @brief Initialize HMAC context with key
 * 
 * @param ctx HMAC context (must be pre-allocated)
 * @param algorithm HMAC algorithm type
 * @param key Secret key for HMAC
 * @param key_len Length of key in bytes
 * @return 0 on success, negative error code on failure
 * 
 * @warning key_len SHOULD be >= output size (32 or 64 bytes depending on algorithm)
 * @warning Keys shorter than 16 bytes are INSECURE for most applications
 * @warning Keys longer than block size will be hashed (reducing effective entropy)
 * 
 * Key handling:
 * - If key_len > block_size: key = H(key)
 * - If key_len < block_size: key is zero-padded to block_size
 * - Processed key is stored internally (K ⊕ ipad, K ⊕ opad)
 * 
 * Security requirements:
 * - Key MUST be randomly generated (use DRBG or entropy source)
 * - Key SHOULD be kept secret and protected
 * - Different keys for different purposes/algorithms
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_hmac_init(
    nextssl_partial_core_hmac_ctx_t *ctx,
    nextssl_hmac_algorithm_t algorithm,
    const uint8_t *key,
    size_t key_len
);

/**
 * @brief Update HMAC with message data (streaming)
 * 
 * @param ctx HMAC context
 * @param data Message data to authenticate
 * @param data_len Length of data in bytes
 * @return 0 on success, negative error code on failure
 * 
 * @note Can be called multiple times to process message in chunks
 * @note Order of update calls MUST match message structure
 * 
 * Example usage (streaming):
 * ```c
 * nextssl_partial_core_hmac_init(&ctx, NEXTSSL_HMAC_SHA256, key, 32);
 * nextssl_partial_core_hmac_update(&ctx, chunk1, len1);
 * nextssl_partial_core_hmac_update(&ctx, chunk2, len2);
 * nextssl_partial_core_hmac_final(&ctx, mac);
 * ```
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_hmac_update(
    nextssl_partial_core_hmac_ctx_t *ctx,
    const uint8_t *data,
    size_t data_len
);

/**
 * @brief Finalize HMAC and output MAC tag
 * 
 * @param ctx HMAC context
 * @param output Output buffer for MAC tag (size depends on algorithm)
 * @return 0 on success, negative error code on failure
 * 
 * @warning output buffer MUST be at least NEXTSSL_HMAC_*_SIZE bytes
 * @warning After final(), context is reset and cannot be reused without re-init
 * 
 * Output sizes:
 * - HMAC-SHA-256: 32 bytes
 * - HMAC-SHA-512: 64 bytes
 * - HMAC-SHA3-256: 32 bytes
 * - HMAC-SHA3-512: 64 bytes
 * - HMAC-BLAKE2b: 64 bytes
 * - HMAC-BLAKE2s: 32 bytes
 * 
 * @note Context state is securely wiped after finalization
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_hmac_final(
    nextssl_partial_core_hmac_ctx_t *ctx,
    uint8_t *output
);

/**
 * @brief Reset HMAC context for reuse with same key
 * 
 * @param ctx HMAC context
 * @return 0 on success, negative error code on failure
 * 
 * @note Keeps the processed key (K ⊕ ipad, K ⊕ opad) intact
 * @note Resets hash state to initial values
 * @note More efficient than destroy + init when using same key
 * 
 * Use case: Authenticating multiple messages with same key
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_hmac_reset(nextssl_partial_core_hmac_ctx_t *ctx);

/**
 * @brief Destroy HMAC context and securely wipe state
 * 
 * @param ctx HMAC context to destroy
 * 
 * @note Wipes processed key material from memory
 * @note Safe to call on already-destroyed or NULL contexts
 */
NEXTSSL_PARTIAL_API void
nextssl_partial_core_hmac_destroy(nextssl_partial_core_hmac_ctx_t *ctx);

/* ========================================================================
 * HMAC One-Shot Functions
 * ======================================================================== */

/**
 * @brief Compute HMAC in one shot (non-streaming)
 * 
 * @param algorithm HMAC algorithm type
 * @param key Secret key
 * @param key_len Length of key in bytes
 * @param data Message data to authenticate
 * @param data_len Length of message data
 * @param output Output buffer for MAC tag
 * @return 0 on success, negative error code on failure
 * 
 * @warning key_len SHOULD be >= output size
 * @warning output buffer MUST be at least NEXTSSL_HMAC_*_SIZE bytes
 * 
 * @note This is a convenience function equivalent to init + update + final
 * @note More efficient than streaming API for small messages
 * 
 * Example:
 * ```c
 * uint8_t mac[32];
 * nextssl_partial_core_hmac(NEXTSSL_HMAC_SHA256, key, 32, msg, msg_len, mac);
 * ```
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_hmac(
    nextssl_hmac_algorithm_t algorithm,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *data,
    size_t data_len,
    uint8_t *output
);

/* ========================================================================
 * HMAC Utility Functions
 * ======================================================================== */

/**
 * @brief Get HMAC output size for algorithm
 * 
 * @param algorithm HMAC algorithm type
 * @return Output size in bytes, or 0 if algorithm invalid
 * 
 * Output sizes:
 * - SHA-256: 32 bytes
 * - SHA-512: 64 bytes
 * - SHA3-256: 32 bytes
 * - SHA3-512: 64 bytes
 * - BLAKE2b: 64 bytes
 * - BLAKE2s: 32 bytes
 */
NEXTSSL_PARTIAL_API size_t
nextssl_partial_core_hmac_output_size(nextssl_hmac_algorithm_t algorithm);

/**
 * @brief Get HMAC block size for algorithm
 * 
 * @param algorithm HMAC algorithm type
 * @return Block size in bytes, or 0 if algorithm invalid
 * 
 * @note Block size is the internal hash block size used for key processing
 * @note Keys longer than block size are hashed before use
 */
NEXTSSL_PARTIAL_API size_t
nextssl_partial_core_hmac_block_size(nextssl_hmac_algorithm_t algorithm);

/**
 * @brief Constant-time MAC verification
 * 
 * @param mac1 First MAC tag
 * @param mac2 Second MAC tag
 * @param mac_len Length of MAC tags (must be same)
 * @return 1 if MACs are equal, 0 if different
 * 
 * @warning ALWAYS use this for MAC verification, NEVER use memcmp()
 * @warning Protects against timing attacks that reveal MAC differences
 * 
 * Example:
 * ```c
 * uint8_t computed_mac[32], received_mac[32];
 * nextssl_partial_core_hmac(algo, key, klen, data, dlen, computed_mac);
 * if (nextssl_partial_core_hmac_verify(computed_mac, received_mac, 32)) {
 *     // MAC is valid
 * } else {
 *     // MAC is invalid (authentication failure)
 * }
 * ```
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_hmac_verify(
    const uint8_t *mac1,
    const uint8_t *mac2,
    size_t mac_len
);

/**
 * @brief Self-test HMAC implementation against RFC test vectors
 * 
 * @param algorithm HMAC algorithm to test
 * @return 0 if all tests pass, negative error code on failure
 * 
 * @note Runs RFC 2104 and RFC 4231 test vectors
 * @note Should be run during library initialization
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_hmac_selftest(nextssl_hmac_algorithm_t algorithm);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_CORE_HMAC_H */

/**
 * Implementation Notes:
 * 
 * 1. HMAC Construction (RFC 2104):
 *    HMAC(K, M) = H((K ⊕ opad) || H((K ⊕ ipad) || M))
 *    - ipad = 0x36 repeated block_size times
 *    - opad = 0x5c repeated block_size times
 *    - If |K| > block_size: K = H(K)
 *    - If |K| < block_size: K is zero-padded to block_size
 * 
 * 2. Algorithm-Specific Details:
 *    - SHA-256: 256-bit output, 512-bit block size
 *    - SHA-512: 512-bit output, 1024-bit block size
 *    - SHA3: Different construction (no padding needed), but HMAC-SHA3 still uses standard HMAC
 *    - BLAKE2: Has built-in keyed mode, but HMAC-BLAKE2 uses standard HMAC for compatibility
 * 
 * 3. Context Structure:
 *    - Inner hash context (for H((K ⊕ ipad) || M))
 *    - Outer hash context (for H((K ⊕ opad) || ...))
 *    - Processed key storage (K ⊕ ipad, K ⊕ opad)
 *    - Algorithm identifier
 * 
 * 4. Streaming vs One-Shot:
 *    - Streaming: init -> update (repeated) -> final (better for large messages)
 *    - One-shot: single function call (better for small messages, less state)
 * 
 * 5. Key Length Recommendations:
 *    - Minimum: 16 bytes (128 bits) - adequate for most uses
 *    - Recommended: Equal to output size (32 or 64 bytes)
 *    - Maximum useful: Equal to block size (64 or 128 bytes)
 *    - Longer keys are hashed, not more secure
 * 
 * 6. Security Considerations:
 *    - HMAC is a PRF (pseudorandom function) - suitable for key derivation
 *    - Resistant to length extension (unlike H(K || M))
 *    - Timing-safe verification REQUIRED (use hmac_verify, not memcmp)
 *    - Key reuse: acceptable for HMAC, but use different keys for different purposes
 * 
 * SECURITY AUDIT NOTES:
 * - [ ] Verify constant-time MAC comparison in hmac_verify()
 * - [ ] Check secure key wiping in destroy()
 * - [ ] Validate key processing (hash long keys, pad short keys)
 * - [ ] Test RFC 2104 and RFC 4231 test vectors
 * - [ ] Verify ipad/opad constants (0x36, 0x5c)
 * - [ ] Check that reset() properly resets hash state
 * - [ ] Ensure no key material leaks in error paths
 */
