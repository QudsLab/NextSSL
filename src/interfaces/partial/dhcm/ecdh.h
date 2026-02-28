/**
 * @file ecdh.h
 * @brief Layer 1 (Partial) - ECDH (Elliptic Curve Diffie-Hellman) Interface
 * 
 * @visibility HIDDEN (NEXTSSL_PARTIAL_API)
 * @layer 1
 * @category dhcm
 * @subcategory ecdh
 * 
 * This interface provides ECDH key agreement on NIST standard curves.
 * Supports P-256 (secp256r1), P-384 (secp384r1), and P-521 (secp521r1).
 * 
 * Security properties:
 * - Computational Diffie-Hellman (CDH) assumption
 * - Forward secrecy (ephemeral keys only)
 * - Passive security (active attacks require authenticated key exchange)
 * - Does NOT provide authentication (use with signatures or MAC)
 * 
 * @warning ECDH alone does NOT authenticate parties - combine with signatures
 * @warning Always validate received public keys before computing shared secret
 * @warning Ephemeral keys MUST be destroyed after key agreement
 * @warning Use KDF (e.g., HKDF) to derive session keys from shared secret
 * 
 * NIST Curve Recommendations:
 * - P-256: 128-bit security, fast, widely supported
 * - P-384: 192-bit security, moderate speed
 * - P-521: 256-bit security, slower but highest security
 * 
 * Thread safety: All functions are thread-safe (stateless operations).
 */

#ifndef NEXTSSL_PARTIAL_DHCM_ECDH_H
#define NEXTSSL_PARTIAL_DHCM_ECDH_H

#include <stddef.h>
#include <stdint.h>
#include "../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * ECDH Types and Constants
 * ======================================================================== */

/**
 * @brief Opaque ECDH context structure
 * 
 * Internal state:
 * - Curve parameters (domain parameters)
 * - Private key (scalar)
 * - Public key (point)
 * - Temporary computation state
 */
typedef struct nextssl_partial_dhcm_ecdh_ctx nextssl_partial_dhcm_ecdh_ctx_t;

/**
 * @brief ECDH curve types (NIST standard curves)
 */
typedef enum {
    NEXTSSL_ECDH_P256,      /**< NIST P-256 / secp256r1 (128-bit security) */
    NEXTSSL_ECDH_P384,      /**< NIST P-384 / secp384r1 (192-bit security) */
    NEXTSSL_ECDH_P521       /**< NIST P-521 / secp521r1 (256-bit security) */
} nextssl_ecdh_curve_t;

/* ECDH key sizes (compressed public key = 1 byte + x-coordinate) */
#define NEXTSSL_ECDH_P256_PRIVKEY_SIZE    32    /**< P-256 private key size */
#define NEXTSSL_ECDH_P256_PUBKEY_SIZE     65    /**< P-256 uncompressed public key (0x04 || x || y) */
#define NEXTSSL_ECDH_P256_COMPRESSED_SIZE 33    /**< P-256 compressed public key (0x02/0x03 || x) */
#define NEXTSSL_ECDH_P256_SECRET_SIZE     32    /**< P-256 shared secret size */

#define NEXTSSL_ECDH_P384_PRIVKEY_SIZE    48    /**< P-384 private key size */
#define NEXTSSL_ECDH_P384_PUBKEY_SIZE     97    /**< P-384 uncompressed public key */
#define NEXTSSL_ECDH_P384_COMPRESSED_SIZE 49    /**< P-384 compressed public key */
#define NEXTSSL_ECDH_P384_SECRET_SIZE     48    /**< P-384 shared secret size */

#define NEXTSSL_ECDH_P521_PRIVKEY_SIZE    66    /**< P-521 private key size */
#define NEXTSSL_ECDH_P521_PUBKEY_SIZE     133   /**< P-521 uncompressed public key */
#define NEXTSSL_ECDH_P521_COMPRESSED_SIZE 67    /**< P-521 compressed public key */
#define NEXTSSL_ECDH_P521_SECRET_SIZE     66    /**< P-521 shared secret size */

#define NEXTSSL_ECDH_MAX_PRIVKEY_SIZE     66    /**< Maximum private key size */
#define NEXTSSL_ECDH_MAX_PUBKEY_SIZE      133   /**< Maximum uncompressed public key size */
#define NEXTSSL_ECDH_MAX_SECRET_SIZE      66    /**< Maximum shared secret size */

/* ========================================================================
 * ECDH Lifecycle Functions
 * ======================================================================== */

/**
 * @brief Get required size for ECDH context allocation
 * 
 * @param curve ECDH curve type
 * @return Size in bytes needed for context, or 0 if curve invalid
 * 
 * @note Always call this before allocating context memory
 */
NEXTSSL_PARTIAL_API size_t
nextssl_partial_dhcm_ecdh_ctx_size(nextssl_ecdh_curve_t curve);

/**
 * @brief Initialize ECDH context
 * 
 * @param ctx ECDH context (must be pre-allocated)
 * @param curve ECDH curve type
 * @return 0 on success, negative error code on failure
 * 
 * @note This does NOT generate keys - use ecdh_generate_keypair()
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_dhcm_ecdh_init(
    nextssl_partial_dhcm_ecdh_ctx_t *ctx,
    nextssl_ecdh_curve_t curve
);

/**
 * @brief Generate ECDH keypair (ephemeral or long-term)
 * 
 * @param ctx ECDH context
 * @param private_key Output buffer for private key
 * @param public_key Output buffer for public key (uncompressed format)
 * @return 0 on success, negative error code on failure
 * 
 * @warning private_key MUST be NEXTSSL_ECDH_*_PRIVKEY_SIZE bytes
 * @warning public_key MUST be NEXTSSL_ECDH_*_PUBKEY_SIZE bytes
 * @warning Private key MUST be kept secret and destroyed after use
 * 
 * Public key format (uncompressed):
 * - Byte 0: 0x04 (uncompressed point indicator)
 * - Bytes 1..n: x-coordinate
 * - Bytes n+1..2n: y-coordinate
 * 
 * @note Uses DRBG for key generation (cryptographically secure)
 * @note For ephemeral keys, destroy context immediately after key agreement
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_dhcm_ecdh_generate_keypair(
    nextssl_partial_dhcm_ecdh_ctx_t *ctx,
    uint8_t *private_key,
    uint8_t *public_key
);

/**
 * @brief Load existing ECDH keypair into context
 * 
 * @param ctx ECDH context
 * @param private_key Private key (can be NULL if public-key-only operations)
 * @param public_key Public key (uncompressed or compressed format)
 * @param public_key_len Length of public key
 * @return 0 on success, negative error code on failure
 * 
 * @warning public_key is validated (point-on-curve check)
 * @warning If private_key is NULL, only signature verification possible
 * 
 * Supported public key formats:
 * - Uncompressed: 0x04 || x || y (65/97/133 bytes)
 * - Compressed: 0x02/0x03 || x (33/49/67 bytes)
 * 
 * @note Private key is NOT validated (assumed correct from generation)
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_dhcm_ecdh_load_keypair(
    nextssl_partial_dhcm_ecdh_ctx_t *ctx,
    const uint8_t *private_key,
    const uint8_t *public_key,
    size_t public_key_len
);

/**
 * @brief Destroy ECDH context and securely wipe keys
 * 
 * @param ctx ECDH context to destroy
 * 
 * @note MUST be called to prevent private key leakage
 * @note Performs secure memory wiping of private key and state
 * @note Safe to call on already-destroyed or NULL contexts
 */
NEXTSSL_PARTIAL_API void
nextssl_partial_dhcm_ecdh_destroy(nextssl_partial_dhcm_ecdh_ctx_t *ctx);

/* ========================================================================
 * ECDH Key Agreement Functions
 * ======================================================================== */

/**
 * @brief Compute ECDH shared secret
 * 
 * @param ctx ECDH context (with loaded private key)
 * @param peer_public_key Peer's public key (uncompressed or compressed)
 * @param peer_public_key_len Length of peer's public key
 * @param shared_secret Output buffer for shared secret
 * @return 0 on success, negative error code on failure
 * 
 * @warning shared_secret MUST be NEXTSSL_ECDH_*_SECRET_SIZE bytes
 * @warning Peer's public key is VALIDATED before computation (point-on-curve)
 * @warning shared_secret is the x-coordinate of the ECDH point (raw bytes)
 * @warning ALWAYS use KDF (e.g., HKDF) to derive session keys from shared_secret
 * 
 * Shared secret format:
 * - Raw x-coordinate of computed point (32/48/66 bytes depending on curve)
 * - NOT suitable for direct use as encryption key (use HKDF)
 * 
 * Error conditions:
 * - Returns error if peer's public key is invalid (not on curve, point at infinity)
 * - Returns error if private key not loaded
 * 
 * Example usage:
 * ```c
 * uint8_t shared_secret[32];
 * nextssl_partial_dhcm_ecdh_compute(ctx, peer_pubkey, 65, shared_secret);
 * 
 * // Derive session keys using HKDF
 * uint8_t session_key[32];
 * nextssl_partial_core_kdf_hkdf(NEXTSSL_HKDF_SHA256,
 *     NULL, 0,  // no salt
 *     shared_secret, 32,
 *     "session key", 11,
 *     session_key, 32);
 * 
 * // Wipe shared secret
 * nextssl_partial_core_buffer_secure_zero(shared_secret, 32);
 * ```
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_dhcm_ecdh_compute(
    nextssl_partial_dhcm_ecdh_ctx_t *ctx,
    const uint8_t *peer_public_key,
    size_t peer_public_key_len,
    uint8_t *shared_secret
);

/* ========================================================================
 * ECDH Utility Functions
 * ======================================================================== */

/**
 * @brief Validate ECDH public key (point-on-curve check)
 * 
 * @param curve ECDH curve type
 * @param public_key Public key to validate
 * @param public_key_len Length of public key
 * @return 1 if valid, 0 if invalid, negative on error
 * 
 * Checks performed:
 * - Point is on the curve
 * - Point is not the point at infinity
 * - Point has correct order
 * - Format byte is correct (0x04 for uncompressed, 0x02/0x03 for compressed)
 * 
 * @note ALWAYS validate peer public keys before use
 * @note This is CRITICAL for security (prevents invalid curve attacks)
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_dhcm_ecdh_validate_public_key(
    nextssl_ecdh_curve_t curve,
    const uint8_t *public_key,
    size_t public_key_len
);

/**
 * @brief Compress ECDH public key
 * 
 * @param curve ECDH curve type
 * @param uncompressed Uncompressed public key (0x04 || x || y)
 * @param compressed Output buffer for compressed key (0x02/0x03 || x)
 * @return 0 on success, negative error code on failure
 * 
 * @warning uncompressed MUST be NEXTSSL_ECDH_*_PUBKEY_SIZE bytes
 * @warning compressed MUST be NEXTSSL_ECDH_*_COMPRESSED_SIZE bytes
 * 
 * Compression format:
 * - 0x02 || x  (if y is even)
 * - 0x03 || x  (if y is odd)
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_dhcm_ecdh_compress_public_key(
    nextssl_ecdh_curve_t curve,
    const uint8_t *uncompressed,
    uint8_t *compressed
);

/**
 * @brief Decompress ECDH public key
 * 
 * @param curve ECDH curve type
 * @param compressed Compressed public key (0x02/0x03 || x)
 * @param uncompressed Output buffer for uncompressed key (0x04 || x || y)
 * @return 0 on success, negative error code on failure
 * 
 * @warning compressed MUST be NEXTSSL_ECDH_*_COMPRESSED_SIZE bytes
 * @warning uncompressed MUST be NEXTSSL_ECDH_*_PUBKEY_SIZE bytes
 * 
 * @note Decompression requires curve equation solving (slower than compression)
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_dhcm_ecdh_decompress_public_key(
    nextssl_ecdh_curve_t curve,
    const uint8_t *compressed,
    uint8_t *uncompressed
);

/**
 * @brief Get sizes for ECDH curve
 * 
 * @param curve ECDH curve type
 * @param privkey_size Output: private key size (can be NULL)
 * @param pubkey_size Output: uncompressed public key size (can be NULL)
 * @param secret_size Output: shared secret size (can be NULL)
 * @return 0 on success, negative error code if curve invalid
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_dhcm_ecdh_get_sizes(
    nextssl_ecdh_curve_t curve,
    size_t *privkey_size,
    size_t *pubkey_size,
    size_t *secret_size
);

/**
 * @brief Self-test ECDH implementation against NIST test vectors
 * 
 * @param curve ECDH curve to test
 * @return 0 if all tests pass, negative error code on failure
 * 
 * @note Runs NIST CAVP test vectors for selected curve
 * @note Should be run during library initialization
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_dhcm_ecdh_selftest(nextssl_ecdh_curve_t curve);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_DHCM_ECDH_H */

/**
 * Implementation Notes:
 * 
 * 1. Curve Domain Parameters:
 *    P-256: y^2 = x^3 - 3x + b (mod p = 2^256 - 2^224 + 2^192 + 2^96 - 1)
 *    P-384: y^2 = x^3 - 3x + b (mod p = 2^384 - 2^128 - 2^96 + 2^32 - 1)
 *    P-521: y^2 = x^3 - 3x + b (mod p = 2^521 - 1)
 * 
 * 2. ECDH Protocol:
 *    Alice: private key a, public key A = aG
 *    Bob: private key b, public key B = bG
 *    Shared secret: S = aB = bA = abG (x-coordinate only)
 * 
 * 3. Public Key Validation (CRITICAL):
 *    - Check point is on curve: y^2 = x^3 - 3x + b
 *    - Check point is not identity (point at infinity)
 *    - Check point order: n * P = O (where n is curve order)
 *    - Prevents invalid curve attacks and small subgroup attacks
 * 
 * 4. Key Derivation:
 *    - Raw shared secret (x-coordinate) is NOT directly usable
 *    - MUST use KDF (HKDF recommended) to derive session keys
 *    - Include context/application info in KDF for domain separation
 * 
 * 5. Authentication:
 *    - ECDH provides confidentiality, NOT authentication
 *    - Combine with signatures (ECDSA) or MAC (HMAC) for authenticated key exchange
 *    - Or use ECIES (Elliptic Curve Integrated Encryption Scheme)
 * 
 * 6. Performance Considerations:
 *    - P-256: ~0.3 ms per key agreement (typical)
 *    - P-384: ~0.8 ms per key agreement
 *    - P-521: ~1.5 ms per key agreement
 *    - Use P-256 for most applications, P-384/P-521 for high security
 * 
 * SECURITY AUDIT NOTES:
 * - [ ] Verify public key validation (point-on-curve, order check)
 * - [ ] Check private key generation uses DRBG
 * - [ ] Validate secure memory wiping in destroy()
 * - [ ] Test NIST CAVP test vectors for all curves
 * - [ ] Verify compressed/uncompressed key conversion
 * - [ ] Check that shared secret is x-coordinate only
 * - [ ] Ensure no timing side-channels in scalar multiplication
 */
