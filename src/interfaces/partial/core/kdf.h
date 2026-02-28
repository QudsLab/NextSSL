/**
 * @file kdf.h
 * @brief Layer 1 (Partial) - KDF (Key Derivation Function) Interface
 * 
 * @visibility HIDDEN (NEXTSSL_PARTIAL_API)
 * @layer 1
 * @category core
 * @subcategory kdf
 * 
 * This interface provides key derivation functions for generating cryptographic keys
 * from passwords, shared secrets, or other key material.
 * 
 * Supported KDFs:
 * - HKDF (RFC 5869) - Extract-and-expand for high-entropy input
 * - PBKDF2 (RFC 2898) - Password-based with iteration count
 * - Argon2 (RFC 9106) - Memory-hard password hashing (preferred for passwords)
 * - ANSI X9.63 KDF - For ECDH key agreement
 * - Concatenation KDF (NIST SP 800-56C) - Simple concatenation-based KDF
 * 
 * Security properties:
 * - Key separation (derive multiple independent keys from one master)
 * - Domain separation (salt/info parameters prevent key reuse)
 * - Stretch weak keys (PBKDF2, Argon2)
 * - Forward secrecy (input key material can be erased after derivation)
 * 
 * @warning Password-based KDFs (PBKDF2, Argon2) MUST use high iteration counts
 * @warning Always use unique salts for each KDF invocation
 * @warning For passwords, prefer Argon2 over PBKDF2
 * 
 * Thread safety: All KDF functions are thread-safe (stateless operations).
 */

#ifndef NEXTSSL_PARTIAL_CORE_KDF_H
#define NEXTSSL_PARTIAL_CORE_KDF_H

#include <stddef.h>
#include <stdint.h>
#include "../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * HKDF (HMAC-based Key Derivation Function)
 * RFC 5869
 * ======================================================================== */

/**
 * @brief HKDF hash algorithm types
 */
typedef enum {
    NEXTSSL_HKDF_SHA256,      /**< HKDF-SHA-256 */
    NEXTSSL_HKDF_SHA512,      /**< HKDF-SHA-512 */
    NEXTSSL_HKDF_SHA3_256,    /**< HKDF-SHA3-256 */
    NEXTSSL_HKDF_SHA3_512     /**< HKDF-SHA3-512 */
} nextssl_hkdf_algorithm_t;

/**
 * @brief HKDF extract-and-expand (full HKDF)
 * 
 * @param algorithm Hash algorithm for HKDF
 * @param salt Optional salt value (can be NULL)
 * @param salt_len Length of salt (0 if salt is NULL)
 * @param ikm Input key material (master secret)
 * @param ikm_len Length of input key material
 * @param info Optional context/application info (can be NULL)
 * @param info_len Length of info (0 if info is NULL)
 * @param okm Output key material buffer
 * @param okm_len Desired length of output key material
 * @return 0 on success, negative error code on failure
 * 
 * HKDF = HKDF-Expand(HKDF-Extract(salt, IKM), info, L)
 * 
 * @warning okm_len MUST be <= 255 * hash_size (8160 bytes for SHA-256)
 * @warning salt SHOULD be unique for each KDF invocation (or NULL for default)
 * @warning info provides domain separation (e.g., "TLS 1.3 handshake key")
 * 
 * Use cases:
 * - Deriving session keys from ECDH shared secret
 * - Expanding master secrets into multiple encryption/MAC keys
 * - Key ratcheting in messaging protocols
 * 
 * Example:
 * ```c
 * uint8_t okm[64];
 * nextssl_partial_core_kdf_hkdf(
 *     NEXTSSL_HKDF_SHA256,
 *     salt, 16,
 *     shared_secret, 32,
 *     "app v1.0", 8,
 *     okm, 64
 * );
 * ```
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_kdf_hkdf(
    nextssl_hkdf_algorithm_t algorithm,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *ikm,
    size_t ikm_len,
    const uint8_t *info,
    size_t info_len,
    uint8_t *okm,
    size_t okm_len
);

/**
 * @brief HKDF-Extract only (first step of HKDF)
 * 
 * @param algorithm Hash algorithm
 * @param salt Optional salt value
 * @param salt_len Length of salt
 * @param ikm Input key material
 * @param ikm_len Length of IKM
 * @param prk Pseudorandom key output (size = hash_size)
 * @return 0 on success, negative error code on failure
 * 
 * PRK = HMAC-Hash(salt, IKM)
 * 
 * @warning prk buffer MUST be at least hash_size bytes (32 for SHA-256, 64 for SHA-512)
 * 
 * Use case: When PRK needs to be stored for later HKDF-Expand calls
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_kdf_hkdf_extract(
    nextssl_hkdf_algorithm_t algorithm,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *ikm,
    size_t ikm_len,
    uint8_t *prk
);

/**
 * @brief HKDF-Expand only (second step of HKDF)
 * 
 * @param algorithm Hash algorithm
 * @param prk Pseudorandom key from HKDF-Extract
 * @param prk_len Length of PRK (should be hash_size)
 * @param info Optional context/application info
 * @param info_len Length of info
 * @param okm Output key material buffer
 * @param okm_len Desired length of output
 * @return 0 on success, negative error code on failure
 * 
 * OKM = HKDF-Expand(PRK, info, L)
 * 
 * @warning okm_len MUST be <= 255 * hash_size
 * @warning prk_len SHOULD be hash_size (32 for SHA-256, 64 for SHA-512)
 * 
 * Use case: Deriving multiple keys from one PRK with different info strings
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_kdf_hkdf_expand(
    nextssl_hkdf_algorithm_t algorithm,
    const uint8_t *prk,
    size_t prk_len,
    const uint8_t *info,
    size_t info_len,
    uint8_t *okm,
    size_t okm_len
);

/* ========================================================================
 * PBKDF2 (Password-Based Key Derivation Function 2)
 * RFC 2898
 * ======================================================================== */

/**
 * @brief PBKDF2 hash algorithm types
 */
typedef enum {
    NEXTSSL_PBKDF2_SHA256,      /**< PBKDF2-HMAC-SHA-256 */
    NEXTSSL_PBKDF2_SHA512       /**< PBKDF2-HMAC-SHA-512 */
} nextssl_pbkdf2_algorithm_t;

/**
 * @brief PBKDF2 key derivation from password
 * 
 * @param algorithm Hash algorithm for PBKDF2
 * @param password Password/passphrase
 * @param password_len Length of password
 * @param salt Salt value (MUST be random and unique)
 * @param salt_len Length of salt (min 16 bytes recommended)
 * @param iterations Iteration count (min 100000 for 2023+)
 * @param dkm Derived key material output buffer
 * @param dkm_len Desired length of derived key
 * @return 0 on success, negative error code on failure
 * 
 * DKM = PBKDF2(PRF, password, salt, iterations, dkLen)
 * 
 * @warning iterations MUST be >= 100000 for SHA-256, >= 210000 for SHA-512 (2023 OWASP)
 * @warning salt MUST be random and unique (16+ bytes)
 * @warning salt_len SHOULD be >= 16 bytes (128 bits)
 * @warning For new applications, prefer Argon2 over PBKDF2
 * 
 * Iteration count recommendations (2023+):
 * - Minimum: 100,000 iterations (SHA-256), 210,000 (SHA-512)
 * - Recommended: 600,000 iterations (OWASP 2023)
 * - High security: 1,000,000+ iterations
 * 
 * Use cases:
 * - Deriving encryption keys from passwords
 * - Password hashing (but Argon2 is better)
 * - Legacy application compatibility
 * 
 * Example:
 * ```c
 * uint8_t key[32];
 * nextssl_partial_core_kdf_pbkdf2(
 *     NEXTSSL_PBKDF2_SHA256,
 *     password, password_len,
 *     salt, 16,
 *     600000,  // OWASP 2023 recommendation
 *     key, 32
 * );
 * ```
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_kdf_pbkdf2(
    nextssl_pbkdf2_algorithm_t algorithm,
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    uint32_t iterations,
    uint8_t *dkm,
    size_t dkm_len
);

/* ========================================================================
 * Argon2 (Memory-hard Password Hashing)
 * RFC 9106
 * ======================================================================== */

/**
 * @brief Argon2 variant types
 */
typedef enum {
    NEXTSSL_ARGON2_I,      /**< Argon2i - Resistant to side-channel attacks */
    NEXTSSL_ARGON2_D,      /**< Argon2d - Resistant to GPU cracking (faster) */
    NEXTSSL_ARGON2_ID      /**< Argon2id - Hybrid (recommended for passwords) */
} nextssl_argon2_type_t;

/**
 * @brief Argon2 key derivation from password
 * 
 * @param type Argon2 variant (i, d, or id)
 * @param password Password/passphrase
 * @param password_len Length of password
 * @param salt Salt value (MUST be random and unique)
 * @param salt_len Length of salt (min 16 bytes)
 * @param time_cost Time cost parameter (iterations)
 * @param memory_cost Memory cost in KiB (e.g., 65536 = 64 MiB)
 * @param parallelism Degree of parallelism (threads)
 * @param hash_output Output hash buffer
 * @param hash_len Desired output length (min 16 bytes)
 * @return 0 on success, negative error code on failure
 * 
 * @warning salt_len MUST be >= 16 bytes
 * @warning hash_len MUST be >= 16 bytes
 * @warning memory_cost SHOULD be >= 65536 KiB (64 MiB) for passwords
 * @warning time_cost SHOULD be >= 3 for passwords
 * @warning parallelism SHOULD be 1-4 depending on available cores
 * 
 * Recommended parameters (2023, OWASP):
 * - Type: NEXTSSL_ARGON2_ID (hybrid, best for passwords)
 * - Memory: 65536 KiB (64 MiB) minimum, 512 MiB preferred
 * - Time: 3 iterations minimum, 5-10 preferred
 * - Parallelism: 1 (single-threaded) or 4 (multi-core)
 * 
 * Variant comparison:
 * - Argon2i: Side-channel resistant, slower
 * - Argon2d: GPU-resistant, faster, vulnerable to side-channels
 * - Argon2id: Best of both (recommended)
 * 
 * Use cases:
 * - Password hashing (preferred over PBKDF2)
 * - Key derivation from passwords
 * - Wallet key derivation
 * 
 * Example (OWASP 2023 recommended):
 * ```c
 * uint8_t hash[32];
 * nextssl_partial_core_kdf_argon2(
 *     NEXTSSL_ARGON2_ID,
 *     password, password_len,
 *     salt, 16,
 *     3,        // time cost
 *     65536,    // memory cost (64 MiB)
 *     4,        // parallelism
 *     hash, 32
 * );
 * ```
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_kdf_argon2(
    nextssl_argon2_type_t type,
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    uint32_t time_cost,
    uint32_t memory_cost,
    uint32_t parallelism,
    uint8_t *hash_output,
    size_t hash_len
);

/* ========================================================================
 * ANSI X9.63 KDF (for ECDH key agreement)
 * ======================================================================== */

/**
 * @brief ANSI X9.63 KDF
 * 
 * @param hash_algorithm Hash algorithm (SHA-256 or SHA-512)
 * @param shared_secret Shared secret from ECDH
 * @param shared_secret_len Length of shared secret
 * @param shared_info Optional shared information
 * @param shared_info_len Length of shared info (0 if NULL)
 * @param output Output key material buffer
 * @param output_len Desired output length
 * @return 0 on success, negative error code on failure
 * 
 * KM = KDF(Z, SharedInfo, keydatalen)
 * 
 * @warning output_len MUST be <= hash_size * (2^32 - 1)
 * 
 * Use case: Key derivation after ECDH key agreement (legacy)
 * 
 * @note For new applications, prefer HKDF over ANSI X9.63 KDF
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_kdf_x963(
    nextssl_hkdf_algorithm_t hash_algorithm,
    const uint8_t *shared_secret,
    size_t shared_secret_len,
    const uint8_t *shared_info,
    size_t shared_info_len,
    uint8_t *output,
    size_t output_len
);

/* ========================================================================
 * KDF Utility Functions
 * ======================================================================== */

/**
 * @brief Self-test KDF implementations against test vectors
 * 
 * @return 0 if all tests pass, negative error code on failure
 * 
 * Tests:
 * - HKDF test vectors (RFC 5869)
 * - PBKDF2 test vectors (RFC 6070)
 * - Argon2 test vectors (RFC 9106)
 * 
 * @note Should be run during library initialization
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_kdf_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_CORE_KDF_H */

/**
 * Implementation Notes:
 * 
 * 1. HKDF (RFC 5869):
 *    - Extract: PRK = HMAC-Hash(salt, IKM)
 *    - Expand: T(0) = empty, T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
 *    - OKM = first L bytes of T(1) || T(2) || ...
 *    - Limit: L <= 255 * HashLen
 * 
 * 2. PBKDF2 (RFC 2898):
 *    - DK = PBKDF2(PRF, Password, Salt, c, dkLen)
 *    - U1 = PRF(Password, Salt || INT_32_BE(i))
 *    - U2 = PRF(Password, U1), ..., Uc = PRF(Password, Uc-1)
 *    - T(i) = U1 XOR U2 XOR ... XOR Uc
 *    - DK = T(1) || T(2) || ... || T(dkLen/hLen)
 * 
 * 3. Argon2 (RFC 9106):
 *    - Three variants: Argon2i, Argon2d, Argon2id
 *    - Memory-hard: Uses large memory buffer (protects against ASICs/GPUs)
 *    - Time-cost: Number of passes over memory
 *    - Parallelism: Number of parallel lanes
 *    - Output: H(password || salt || params || memory_content)
 * 
 * 4. ANSI X9.63 KDF:
 *    - K(i) = Hash(Z || Counter(i) || SharedInfo)
 *    - KM = K(1) || K(2) || ... (first keydatalen bits)
 *    - Counter is 32-bit big-endian integer starting at 1
 * 
 * 5. Parameter Recommendations (2023):
 *    - HKDF: salt >= 16 bytes (random), info for domain separation
 *    - PBKDF2: iterations >= 600000 (SHA-256), salt >= 16 bytes
 *    - Argon2id: memory >= 64 MiB, time >= 3, parallelism = 1-4
 *    - Prefer Argon2 for passwords, HKDF for key expansion
 * 
 * 6. Use Case Selection:
 *    - High-entropy input (e.g., ECDH secret): HKDF
 *    - Password to key: Argon2id > PBKDF2
 *    - Multiple keys from one master: HKDF-Expand with different info
 *    - Legacy ECDH: ANSI X9.63 KDF (or upgrade to HKDF)
 * 
 * SECURITY AUDIT NOTES:
 * - [ ] Verify HKDF extract/expand logic (RFC 5869 compliance)
 * - [ ] Check PBKDF2 iteration count enforcement (min 100000)
 * - [ ] Validate Argon2 memory allocation and access patterns
 * - [ ] Test against RFC/NIST test vectors for all KDFs
 * - [ ] Verify salt uniqueness requirements
 * - [ ] Check output length limits for each KDF
 * - [ ] Ensure secure wiping of intermediate values
 */
