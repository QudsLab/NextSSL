/**
 * @file ml_kem.h
 * @brief Layer 1 (Partial) - ML-KEM (Module-Lattice Key Encapsulation Mechanism) Interface
 * 
 * @visibility HIDDEN (NEXTSSL_PARTIAL_API)
 * @layer 1
 * @category dhcm
 * @subcategory ml_kem
 * 
 * This interface provides ML-KEM (NIST FIPS 203) - the standardized post-quantum KEM.
 * ML-KEM is based on CRYSTALS-Kyber with NIST-specified modifications.
 * 
 * **USE THIS FOR NEW APPLICATIONS** (not the legacy Kyber interface)
 * 
 * Security properties:
 * - Post-quantum secure (resistant to Shor's algorithm)
 * - IND-CCA2 secure (indistinguishability under adaptive chosen ciphertext attack)
 * - Based on Module-LWE (Learning With Errors over module lattices)
 * - ML-KEM-512: NIST Category 1 (~AES-128 post-quantum security)
 * - ML-KEM-768: NIST Category 3 (~AES-192 post-quantum security)
 * - ML-KEM-1024: NIST Category 5 (~AES-256 post-quantum security)
 * 
 * @warning NOT compatible with Kyber Round 3 (use kyber.h for backward compat)
 * @warning Always use proper key derivation (HKDF) on shared secret
 * @warning Recommended: Hybrid mode with X25519 for defense-in-depth
 * 
 * NIST FIPS 203 (August 2024):
 * - Final standardized version
 * - Mandatory for US federal systems by 2030
 * - Replaces RSA/ECC for key establishment in post-quantum era
 * 
 * Thread safety: All functions are thread-safe (stateless operations).
 */

#ifndef NEXTSSL_PARTIAL_DHCM_ML_KEM_H
#define NEXTSSL_PARTIAL_DHCM_ML_KEM_H

#include <stddef.h>
#include <stdint.h>
#include "../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * ML-KEM Types and Constants (NIST FIPS 203)
 * ======================================================================== */

/**
 * @brief ML-KEM parameter sets (NIST FIPS 203)
 */
typedef enum {
    NEXTSSL_ML_KEM_512,      /**< ML-KEM-512 (NIST Category 1, ~AES-128 PQ) */
    NEXTSSL_ML_KEM_768,      /**< ML-KEM-768 (NIST Category 3, ~AES-192 PQ) */
    NEXTSSL_ML_KEM_1024      /**< ML-KEM-1024 (NIST Category 5, ~AES-256 PQ) */
} nextssl_ml_kem_variant_t;

/* ML-KEM-512 sizes (NIST FIPS 203) */
#define NEXTSSL_ML_KEM_512_PUBLIC_KEY_SIZE   800    /**< Public key size */
#define NEXTSSL_ML_KEM_512_SECRET_KEY_SIZE   1632   /**< Secret key size */
#define NEXTSSL_ML_KEM_512_CIPHERTEXT_SIZE   768    /**< Ciphertext size */
#define NEXTSSL_ML_KEM_512_SHARED_SECRET_SIZE 32    /**< Shared secret size */

/* ML-KEM-768 sizes */
#define NEXTSSL_ML_KEM_768_PUBLIC_KEY_SIZE   1184   /**< Public key size */
#define NEXTSSL_ML_KEM_768_SECRET_KEY_SIZE   2400   /**< Secret key size */
#define NEXTSSL_ML_KEM_768_CIPHERTEXT_SIZE   1088   /**< Ciphertext size */
#define NEXTSSL_ML_KEM_768_SHARED_SECRET_SIZE 32    /**< Shared secret size */

/* ML-KEM-1024 sizes */
#define NEXTSSL_ML_KEM_1024_PUBLIC_KEY_SIZE   1568  /**< Public key size */
#define NEXTSSL_ML_KEM_1024_SECRET_KEY_SIZE   3168  /**< Secret key size */
#define NEXTSSL_ML_KEM_1024_CIPHERTEXT_SIZE   1568  /**< Ciphertext size */
#define NEXTSSL_ML_KEM_1024_SHARED_SECRET_SIZE 32   /**< Shared secret size */

/* Maximum sizes */
#define NEXTSSL_ML_KEM_MAX_PUBLIC_KEY_SIZE   1568
#define NEXTSSL_ML_KEM_MAX_SECRET_KEY_SIZE   3168
#define NEXTSSL_ML_KEM_MAX_CIPHERTEXT_SIZE   1568
#define NEXTSSL_ML_KEM_MAX_SHARED_SECRET_SIZE 32

/* ========================================================================
 * ML-KEM Key Generation
 * ======================================================================== */

/**
 * @brief Generate ML-KEM keypair
 * 
 * @param variant ML-KEM variant (512, 768, or 1024)
 * @param public_key Output buffer for public key
 * @param secret_key Output buffer for secret key
 * @return 0 on success, negative error code on failure
 * 
 * @warning public_key MUST be NEXTSSL_ML_KEM_*_PUBLIC_KEY_SIZE bytes
 * @warning secret_key MUST be NEXTSSL_ML_KEM_*_SECRET_KEY_SIZE bytes
 * @warning Secret key MUST be kept private and destroyed after expiration
 * 
 * Buffer sizes:
 * - ML-KEM-512: public=800, secret=1632
 * - ML-KEM-768: public=1184, secret=2400
 * - ML-KEM-1024: public=1568, secret=3168
 * 
 * Key generation process:
 * 1. Generate random seed (32 bytes from DRBG)
 * 2. Expand seed using SHAKE-256
 * 3. Generate polynomial matrix A from seed
 * 4. Sample secret polynomial vector s
 * 5. Sample error polynomial vector e
 * 6. Compute public key: t = A*s + e
 * 
 * @note Uses DRBG for random number generation (32 bytes seed)
 * @note Key generation is deterministic given the seed
 * @note FIPS 203 specifies exact key generation algorithm
 * 
 * Example:
 * ```c
 * uint8_t pk[NEXTSSL_ML_KEM_768_PUBLIC_KEY_SIZE];
 * uint8_t sk[NEXTSSL_ML_KEM_768_SECRET_KEY_SIZE];
 * 
 * nextssl_partial_dhcm_ml_kem_generate_keypair(
 *     NEXTSSL_ML_KEM_768,
 *     pk, sk
 * );
 * ```
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_dhcm_ml_kem_generate_keypair(
    nextssl_ml_kem_variant_t variant,
    uint8_t *public_key,
    uint8_t *secret_key
);

/* ========================================================================
 * ML-KEM Encapsulation (Sender/Initiator)
 * ======================================================================== */

/**
 * @brief Encapsulate a shared secret using ML-KEM (sender side)
 * 
 * @param variant ML-KEM variant
 * @param public_key Recipient's public key
 * @param ciphertext Output buffer for ciphertext
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @return 0 on success, negative error code on failure
 * 
 * @warning public_key MUST be NEXTSSL_ML_KEM_*_PUBLIC_KEY_SIZE bytes
 * @warning ciphertext MUST be NEXTSSL_ML_KEM_*_CIPHERTEXT_SIZE bytes
 * @warning shared_secret MUST be 32 bytes (all variants)
 * 
 * Encapsulation process:
 * 1. Generate random message m (32 bytes from DRBG)
 * 2. Compute K = H(m)  (shared secret derivation)
 * 3. Sample random polynomials r, e1, e2
 * 4. Encrypt: c = Encrypt(pk, m, r)
 * 5. Return (c, K)
 * 
 * Protocol:
 * 1. Sender calls this function with recipient's public_key
 * 2. Generates random shared_secret and encrypts it -> ciphertext
 * 3. Sender uses shared_secret for session key derivation (via HKDF)
 * 4. Sender transmits ciphertext to recipient
 * 5. Recipient decapsulates ciphertext to recover shared_secret
 * 
 * Ciphertext sizes:
 * - ML-KEM-512: 768 bytes
 * - ML-KEM-768: 1088 bytes
 * - ML-KEM-1024: 1568 bytes
 * 
 * @note Shared secret is always 32 bytes regardless of variant
 * @note Uses DRBG for randomness (32 bytes)
 * @note Encapsulation is deterministic given the random message m
 * 
 * Example usage:
 * ```c
 * uint8_t pk[NEXTSSL_ML_KEM_768_PUBLIC_KEY_SIZE];
 * uint8_t ct[NEXTSSL_ML_KEM_768_CIPHERTEXT_SIZE];
 * uint8_t ss[32];
 * 
 * // Encapsulate (sender side)
 * nextssl_partial_dhcm_ml_kem_encapsulate(
 *     NEXTSSL_ML_KEM_768,
 *     pk, ct, ss
 * );
 * 
 * // Derive session key
 * uint8_t session_key[32];
 * nextssl_partial_core_kdf_hkdf(
 *     NEXTSSL_HKDF_SHA256,
 *     NULL, 0,  // no salt
 *     ss, 32,
 *     "ml-kem session", 15,
 *     session_key, 32
 * );
 * 
 * // Send ciphertext to recipient
 * ```
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_dhcm_ml_kem_encapsulate(
    nextssl_ml_kem_variant_t variant,
    const uint8_t *public_key,
    uint8_t *ciphertext,
    uint8_t *shared_secret
);

/* ========================================================================
 * ML-KEM Decapsulation (Receiver/Responder)
 * ======================================================================== */

/**
 * @brief Decapsulate a shared secret using ML-KEM (receiver side)
 * 
 * @param variant ML-KEM variant
 * @param secret_key Our secret key
 * @param ciphertext Received ciphertext
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @return 0 on success, negative error code on failure
 * 
 * @warning secret_key MUST be NEXTSSL_ML_KEM_*_SECRET_KEY_SIZE bytes
 * @warning ciphertext MUST be NEXTSSL_ML_KEM_*_CIPHERTEXT_SIZE bytes
 * @warning shared_secret MUST be 32 bytes
 * 
 * Decapsulation process:
 * 1. Decrypt ciphertext: m' = Decrypt(sk, c)
 * 2. Re-encapsulate: c' = Encapsulate(pk, m')
 * 3. If c' == c: K = H(m')  (valid ciphertext)
 * 4. Else: K = H(z)  (invalid ciphertext, implicit reject)
 * 5. Return K
 * 
 * Protocol:
 * 1. Receiver receives ciphertext from sender
 * 2. Receiver calls this function with their secret_key
 * 3. Decapsulates ciphertext to recover shared_secret
 * 4. Receiver uses shared_secret for session key derivation (via HKDF)
 * 
 * @note Shared secret matches sender's shared_secret if no errors
 * @note Constant-time implementation (prevents timing attacks)
 * @note Implicit reject: Always produces output, even on error
 * @note If ciphertext is invalid, shared_secret is pseudorandom (unrelated to sender)
 * 
 * Constant-time guarantees:
 * - Execution time independent of ciphertext validity
 * - No secret-dependent branches
 * - Prevents timing attacks revealing decapsulation failures
 * 
 * Example usage:
 * ```c
 * uint8_t sk[NEXTSSL_ML_KEM_768_SECRET_KEY_SIZE];
 * uint8_t ct[NEXTSSL_ML_KEM_768_CIPHERTEXT_SIZE];
 * uint8_t ss[32];
 * 
 * // Decapsulate (receiver side)
 * int result = nextssl_partial_dhcm_ml_kem_decapsulate(
 *     NEXTSSL_ML_KEM_768,
 *     sk, ct, ss
 * );
 * 
 * // Always derive session key (constant-time)
 * uint8_t session_key[32];
 * nextssl_partial_core_kdf_hkdf(
 *     NEXTSSL_HKDF_SHA256,
 *     NULL, 0,
 *     ss, 32,
 *     "ml-kem session", 15,
 *     session_key, 32
 * );
 * 
 * // Check result (non-constant-time, after key derivation)
 * if (result == 0) {
 *     // Valid ciphertext, proceed with session
 * } else {
 *     // Invalid ciphertext, abort session
 *     // (session_key is pseudorandom, not related to sender)
 * }
 * ```
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_dhcm_ml_kem_decapsulate(
    nextssl_ml_kem_variant_t variant,
    const uint8_t *secret_key,
    const uint8_t *ciphertext,
    uint8_t *shared_secret
);

/* ========================================================================
 * ML-KEM Utility Functions
 * ======================================================================== */

/**
 * @brief Get key sizes for ML-KEM variant
 * 
 * @param variant ML-KEM variant
 * @param public_key_size Output: public key size (can be NULL)
 * @param secret_key_size Output: secret key size (can be NULL)
 * @param ciphertext_size Output: ciphertext size (can be NULL)
 * @param shared_secret_size Output: shared secret size (can be NULL)
 * @return 0 on success, negative error code if variant invalid
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_dhcm_ml_kem_get_sizes(
    nextssl_ml_kem_variant_t variant,
    size_t *public_key_size,
    size_t *secret_key_size,
    size_t *ciphertext_size,
    size_t *shared_secret_size
);

/**
 * @brief Self-test ML-KEM implementation against NIST FIPS 203 test vectors
 * 
 * @param variant ML-KEM variant to test
 * @return 0 if all tests pass, negative error code on failure
 * 
 * @note Runs NIST FIPS 203 known-answer tests
 * @note Should be run during library initialization
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_dhcm_ml_kem_selftest(nextssl_ml_kem_variant_t variant);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_DHCM_ML_KEM_H */

/**
 * Implementation Notes:
 * 
 * 1. ML-KEM Algorithm (NIST FIPS 203):
 *    - Module-LWE based KEM
 *    - IND-CCA2 secure via Fujisaki-Okamoto transform
 *    - Deterministic encapsulation (given random message m)
 *    - Constant-time decapsulation with implicit reject
 * 
 * 2. Parameter Sets (NIST FIPS 203):
 *    - ML-KEM-512: (n=256, k=2, q=3329, η₁=3, η₂=2) - Category 1
 *    - ML-KEM-768: (n=256, k=3, q=3329, η₁=2, η₂=2) - Category 3
 *    - ML-KEM-1024: (n=256, k=4, q=3329, η₁=2, η₂=2) - Category 5
 * 
 * 3. Key Sizes:
 *    - Public key: compressed polynomial vector t + random seed ρ
 *    - Secret key: secret vector s + public key + hash(pk) + random z
 *    - Ciphertext: compressed polynomial vector u + compressed polynomial v
 *    - Shared secret: Always 32 bytes (SHAKE-256 output)
 * 
 * 4. Security Levels (Post-Quantum):
 *    - ML-KEM-512: >2^128 gates (quantum), >2^153 classical
 *    - ML-KEM-768: >2^192 gates (quantum), >2^207 classical
 *    - ML-KEM-1024: >2^256 gates (quantum), >2^254 classical
 * 
 * 5. Differences from Kyber Round 3:
 *    - Domain separation strings (different hash inputs)
 *    - Key derivation slightly modified
 *    - Test vectors completely different
 *    - NOT interoperable with Kyber Round 3
 * 
 * 6. Cryptographic Functions Used:
 *    - SHAKE-128: Expanding A matrix, sampling noise
 *    - SHAKE-256: Key derivation, shared secret generation
 *    - SHA3-256: Hashing public key
 *    - SHA3-512: Hashing secret key components
 * 
 * 7. Implicit Reject (Constant-Time):
 *    - Always produces output (never fails visibly)
 *    - Invalid ciphertext -> pseudorandom shared secret
 *    - Prevents active attacks exploiting failure information
 *    - Critical for IND-CCA2 security
 * 
 * 8. Hybrid Construction (STRONGLY RECOMMENDED):
 *    ML-KEM alone is secure, but defense-in-depth recommends hybrid:
 *    ```
 *    x25519_ss = X25519(our_x25519_sk, peer_x25519_pk)
 *    ml_kem_ss = ML-KEM.Decapsulate(our_ml_kem_sk, ml_kem_ct)
 *    final_ss = HKDF(x25519_ss || ml_kem_ss, "hybrid session key")
 *    ```
 *    Benefits:
 *    - Protects if either algorithm is broken
 *    - Minimal overhead (X25519 is very fast)
 *    - Recommended by NSA, NIST, IETF
 * 
 * 9. Performance (Typical x64 CPU):
 *    - ML-KEM-512: ~0.04 ms keygen, ~0.05 ms encaps, ~0.06 ms decaps
 *    - ML-KEM-768: ~0.07 ms keygen, ~0.08 ms encaps, ~0.09 ms decaps
 *    - ML-KEM-1024: ~0.11 ms keygen, ~0.12 ms encaps, ~0.14 ms decaps
 *    - Suitable for TLS handshakes (minimal latency)
 * 
 * 10. Migration Path:
 *     - 2024-2030: Hybrid X25519+ML-KEM
 *     - 2030+: ML-KEM only (post-quantum transition complete)
 *     - Always support fallback to X25519 for compatibility
 * 
 * 11. Key Lifetime Recommendations:
 *     - Ephemeral keys: Single session, destroy immediately
 *     - Short-term keys: Days to weeks (frequent rotation)
 *     - Long-term keys: Up to 1 year maximum
 *     - Never reuse keys across different contexts
 * 
 * SECURITY AUDIT NOTES:
 * - [ ] Verify constant-time decapsulation (no secret-dependent branches)
 * - [ ] Check implicit reject mechanism (always produces output)
 * - [ ] Validate NTT implementation (modular arithmetic correct)
 * - [ ] Test NIST FIPS 203 known-answer tests (all variants)
 * - [ ] Verify secure memory wiping of secret keys
 * - [ ] Check polynomial coefficient bounds enforcement
 * - [ ] Ensure SHAKE-128/256 implementation correctness
 * - [ ] Validate domain separation strings (FIPS 203 exact values)
 */
