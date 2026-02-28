/**
 * @file kyber.h
 * @brief Layer 1 (Partial) - Kyber KEM (Legacy, Pre-NIST) Interface
 * 
 * @visibility HIDDEN (NEXTSSL_PARTIAL_API)
 * @layer 1
 * @category dhcm
 * @subcategory kyber
 * 
 * This interface provides Kyber KEM (Key Encapsulation Mechanism) - LEGACY VERSION.
 * This is the pre-standardization Kyber from NIST Round 3.
 * 
 * @warning THIS IS LEGACY - Use ML-KEM (ml_kem.h) for new applications
 * @warning Provided ONLY for compatibility with existing deployments
 * @warning NIST standardized ML-KEM has minor changes vs this Kyber
 * 
 * Security properties:
 * - Post-quantum secure (resistant to Shor's algorithm)
 * - IND-CCA2 secure (indistinguishability under adaptive chosen ciphertext attack)
 * - Based on Module-LWE (Learning With Errors over module lattices)
 * - Kyber512: NIST Level 1 (~AES-128 security)
 * - Kyber768: NIST Level 3 (~AES-192 security)
 * - Kyber1024: NIST Level 5 (~AES-256 security)
 * 
 * @warning Use only for backward compatibility with Kyber Round 3 deployments
 * @warning For new code, use ML-KEM (NIST FIPS 203)
 * 
 * Thread safety: All functions are thread-safe (stateless operations).
 */

#ifndef NEXTSSL_PARTIAL_DHCM_KYBER_H
#define NEXTSSL_PARTIAL_DHCM_KYBER_H

#include <stddef.h>
#include <stdint.h>
#include "../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Kyber Types and Constants (NIST Round 3)
 * ======================================================================== */

/**
 * @brief Kyber parameter sets (NIST Round 3)
 */
typedef enum {
    NEXTSSL_KYBER512,      /**< Kyber512 (NIST Level 1, ~AES-128) */
    NEXTSSL_KYBER768,      /**< Kyber768 (NIST Level 3, ~AES-192) */
    NEXTSSL_KYBER1024      /**< Kyber1024 (NIST Level 5, ~AES-256) */
} nextssl_kyber_variant_t;

/* Kyber512 sizes (NIST Round 3) */
#define NEXTSSL_KYBER512_PUBLIC_KEY_SIZE   800    /**< Public key size */
#define NEXTSSL_KYBER512_SECRET_KEY_SIZE   1632   /**< Secret key size */
#define NEXTSSL_KYBER512_CIPHERTEXT_SIZE   768    /**< Ciphertext size */
#define NEXTSSL_KYBER512_SHARED_SECRET_SIZE 32    /**< Shared secret size */

/* Kyber768 sizes */
#define NEXTSSL_KYBER768_PUBLIC_KEY_SIZE   1184   /**< Public key size */
#define NEXTSSL_KYBER768_SECRET_KEY_SIZE   2400   /**< Secret key size */
#define NEXTSSL_KYBER768_CIPHERTEXT_SIZE   1088   /**< Ciphertext size */
#define NEXTSSL_KYBER768_SHARED_SECRET_SIZE 32    /**< Shared secret size */

/* Kyber1024 sizes */
#define NEXTSSL_KYBER1024_PUBLIC_KEY_SIZE   1568  /**< Public key size */
#define NEXTSSL_KYBER1024_SECRET_KEY_SIZE   3168  /**< Secret key size */
#define NEXTSSL_KYBER1024_CIPHERTEXT_SIZE   1568  /**< Ciphertext size */
#define NEXTSSL_KYBER1024_SHARED_SECRET_SIZE 32   /**< Shared secret size */

/* Maximum sizes */
#define NEXTSSL_KYBER_MAX_PUBLIC_KEY_SIZE   1568
#define NEXTSSL_KYBER_MAX_SECRET_KEY_SIZE   3168
#define NEXTSSL_KYBER_MAX_CIPHERTEXT_SIZE   1568
#define NEXTSSL_KYBER_MAX_SHARED_SECRET_SIZE 32

/* ========================================================================
 * Kyber Key Generation
 * ======================================================================== */

/**
 * @brief Generate Kyber keypair
 * 
 * @param variant Kyber variant (512, 768, or 1024)
 * @param public_key Output buffer for public key
 * @param secret_key Output buffer for secret key
 * @return 0 on success, negative error code on failure
 * 
 * @warning public_key MUST be NEXTSSL_KYBER*_PUBLIC_KEY_SIZE bytes
 * @warning secret_key MUST be NEXTSSL_KYBER*_SECRET_KEY_SIZE bytes
 * @warning Secret key MUST be kept private and destroyed after use
 * 
 * Buffer sizes:
 * - Kyber512: public=800, secret=1632
 * - Kyber768: public=1184, secret=2400
 * - Kyber1024: public=1568, secret=3168
 * 
 * @note Uses DRBG for random number generation
 * @note Key generation is deterministic given random seed
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_dhcm_kyber_generate_keypair(
    nextssl_kyber_variant_t variant,
    uint8_t *public_key,
    uint8_t *secret_key
);

/* ========================================================================
 * Kyber Encapsulation (Sender/Initiator)
 * ======================================================================== */

/**
 * @brief Encapsulate a shared secret using Kyber (sender side)
 * 
 * @param variant Kyber variant
 * @param public_key Recipient's public key
 * @param ciphertext Output buffer for ciphertext
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @return 0 on success, negative error code on failure
 * 
 * @warning public_key MUST be NEXTSSL_KYBER*_PUBLIC_KEY_SIZE bytes
 * @warning ciphertext MUST be NEXTSSL_KYBER*_CIPHERTEXT_SIZE bytes
 * @warning shared_secret MUST be 32 bytes (all variants)
 * 
 * Protocol:
 * 1. Sender calls this function with recipient's public_key
 * 2. Generates random shared_secret and encrypts it -> ciphertext
 * 3. Sender uses shared_secret for session key derivation
 * 4. Sender sends ciphertext to recipient
 * 5. Recipient decapsulates ciphertext to recover shared_secret
 * 
 * Ciphertext sizes:
 * - Kyber512: 768 bytes
 * - Kyber768: 1088 bytes
 * - Kyber1024: 1568 bytes
 * 
 * @note Shared secret is always 32 bytes regardless of variant
 * @note Uses DRBG for randomness
 * 
 * Example usage:
 * ```c
 * uint8_t public_key[NEXTSSL_KYBER768_PUBLIC_KEY_SIZE];
 * uint8_t ciphertext[NEXTSSL_KYBER768_CIPHERTEXT_SIZE];
 * uint8_t shared_secret[32];
 * 
 * // Encapsulate (sender side)
 * nextssl_partial_dhcm_kyber_encapsulate(
 *     NEXTSSL_KYBER768,
 *     public_key,
 *     ciphertext,
 *     shared_secret
 * );
 * 
 * // Send ciphertext to recipient
 * // Use shared_secret for key derivation
 * ```
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_dhcm_kyber_encapsulate(
    nextssl_kyber_variant_t variant,
    const uint8_t *public_key,
    uint8_t *ciphertext,
    uint8_t *shared_secret
);

/* ========================================================================
 * Kyber Decapsulation (Receiver/Responder)
 * ======================================================================== */

/**
 * @brief Decapsulate a shared secret using Kyber (receiver side)
 * 
 * @param variant Kyber variant
 * @param secret_key Our secret key
 * @param ciphertext Received ciphertext
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @return 0 on success, negative error code on failure
 * 
 * @warning secret_key MUST be NEXTSSL_KYBER*_SECRET_KEY_SIZE bytes
 * @warning ciphertext MUST be NEXTSSL_KYBER*_CIPHERTEXT_SIZE bytes
 * @warning shared_secret MUST be 32 bytes
 * 
 * Protocol:
 * 1. Receiver receives ciphertext from sender
 * 2. Receiver calls this function with their secret_key
 * 3. Decrypts ciphertext to recover shared_secret
 * 4. Receiver uses shared_secret for session key derivation
 * 
 * @note Shared secret matches sender's shared_secret if no errors
 * @note Constant-time implementation (prevents timing attacks)
 * @note Returns error flag but ALWAYS produces output (implicit reject)
 * 
 * Example usage:
 * ```c
 * uint8_t secret_key[NEXTSSL_KYBER768_SECRET_KEY_SIZE];
 * uint8_t ciphertext[NEXTSSL_KYBER768_CIPHERTEXT_SIZE];
 * uint8_t shared_secret[32];
 * 
 * // Decapsulate (receiver side)
 * int result = nextssl_partial_dhcm_kyber_decaps(
 *     NEXTSSL_KYBER768,
 *     secret_key,
 *     ciphertext,
 *     shared_secret
 * );
 * 
 * if (result == 0) {
 *     // shared_secret is valid
 *     // Use for key derivation
 * } else {
 *     // Decapsulation failed (malformed ciphertext)
 *     // shared_secret is randomized (implicit reject)
 * }
 * ```
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_dhcm_kyber_decapsulate(
    nextssl_kyber_variant_t variant,
    const uint8_t *secret_key,
    const uint8_t *ciphertext,
    uint8_t *shared_secret
);

/* ========================================================================
 * Kyber Utility Functions
 * ======================================================================== */

/**
 * @brief Get key sizes for Kyber variant
 * 
 * @param variant Kyber variant
 * @param public_key_size Output: public key size (can be NULL)
 * @param secret_key_size Output: secret key size (can be NULL)
 * @param ciphertext_size Output: ciphertext size (can be NULL)
 * @param shared_secret_size Output: shared secret size (can be NULL)
 * @return 0 on success, negative error code if variant invalid
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_dhcm_kyber_get_sizes(
    nextssl_kyber_variant_t variant,
    size_t *public_key_size,
    size_t *secret_key_size,
    size_t *ciphertext_size,
    size_t *shared_secret_size
);

/**
 * @brief Self-test Kyber implementation against known-answer tests
 * 
 * @param variant Kyber variant to test
 * @return 0 if all tests pass, negative error code on failure
 * 
 * @note Runs NIST Round 3 test vectors
 * @note Should be run during library initialization
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_dhcm_kyber_selftest(nextssl_kyber_variant_t variant);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_DHCM_KYBER_H */

/**
 * Implementation Notes:
 * 
 * 1. Kyber Algorithm (NIST Round 3):
 *    - Module-LWE based KEM
 *    - IND-CCA2 secure via Fujisaki-Okamoto transform
 *    - Deterministic encapsulation (given random seed)
 *    - Constant-time decapsulation
 * 
 * 2. Parameter Sets:
 *    - Kyber512: (n=256, k=2, q=3329) - NIST Level 1
 *    - Kyber768: (n=256, k=3, q=3329) - NIST Level 3
 *    - Kyber1024: (n=256, k=4, q=3329) - NIST Level 5
 * 
 * 3. Key Sizes:
 *    - Public key: polyvec + seed (compressed)
 *    - Secret key: private polyvec + public key + hash + z
 *    - Ciphertext: compressed polyvec + compressed poly
 *    - Shared secret: Always 32 bytes (SHA3-256 output)
 * 
 * 4. Security Levels:
 *    - Kyber512: Comparable to AES-128 (~2^128 classical, ~2^64 quantum)
 *    - Kyber768: Comparable to AES-192 (~2^192 classical, ~2^96 quantum)
 *    - Kyber1024: Comparable to AES-256 (~2^256 classical, ~2^128 quantum)
 * 
 * 5. Differences from ML-KEM (NIST FIPS 203):
 *    - Minor tweaks to key derivation
 *    - Domain separation strings changed
 *    - Test vectors differ
 *    - Interoperability: Kyber Round 3 != ML-KEM
 * 
 * 6. When to Use This vs ML-KEM:
 *    - Use Kyber: Only for backward compatibility with existing deployments
 *    - Use ML-KEM: All new applications (NIST standardized)
 * 
 * 7. KEM vs ECDH:
 *    - KEM: One-way (encapsulate/decapsulate), no key agreement
 *    - ECDH: Interactive (both parties contribute to secret)
 *    - KEM advantage: Only one round-trip needed
 * 
 * 8. Hybrid Construction (Recommended):
 *    - Combine Kyber with X25519 for defense-in-depth
 *    - shared_secret_final = KDF(kyber_ss || x25519_ss)
 *    - Protects against potential weaknesses in either algorithm
 * 
 * 9. Performance:
 *    - Kyber512: ~0.05 ms encaps, ~0.07 ms decaps
 *    - Kyber768: ~0.08 ms encaps, ~0.10 ms decaps
 *    - Kyber1024: ~0.12 ms encaps, ~0.15 ms decaps
 *    - Much faster than RSA or classical McEliece
 * 
 * 10. Implementation Details:
 *     - NTT (Number Theoretic Transform) for polynomial multiplication
 *     - Modulus q = 3329 (prime, fits in 16 bits)
 *     - Noise from binomial distribution
 *     - Compression reduces ciphertext/public key size
 * 
 * SECURITY AUDIT NOTES:
 * - [ ] Verify constant-time decapsulation
 * - [ ] Check implicit reject mechanism (FO transform)
 * - [ ] Validate NTT implementation
 * - [ ] Test NIST Round 3 known-answer tests
 * - [ ] Verify secure memory wiping
 * - [ ] Check polynomial coefficient bounds
 * - [ ] Ensure no secret-dependent branches in decapsulation
 */
