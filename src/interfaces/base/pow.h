/**
 * @file pow.h
 * @brief Layer 2: Password hashing aggregation
 * @layer base
 * @category pow
 * @visibility semi-public
 * 
 * Memory-hard password hashing functions with safe defaults.
 * 
 * **Recommended algorithms:**
 * - Argon2id (default, PHC winner 2015, RFC 9106)
 * - scrypt (cryptocurrency standard, RFC 7914)
 * - bcrypt (legacy support, widely deployed)
 * 
 * @security All functions use OWASP 2023-recommended parameters as defaults
 */

#ifndef NEXTSSL_BASE_POW_H
#define NEXTSSL_BASE_POW_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* ========== Argon2id (RECOMMENDED) ========== */

/**
 * Hash password with Argon2id (recommended, secure defaults)
 * 
 * @param password Input password
 * @param password_len Length of password
 * @param hash_out Output buffer for encoded hash (256 bytes minimum)
 * @param hash_out_len Size of output buffer
 * @return 0 on success, negative on error
 * 
 * @note Uses OWASP 2023 defaults: t=4, m=256MB, p=4
 * @compliance RFC 9106
 * @security Best general-purpose password hashing algorithm
 */
NEXTSSL_BASE_API int nextssl_base_pow_argon2id_hash(
    const uint8_t *password, size_t password_len,
    char *hash_out, size_t hash_out_len);

/**
 * Hash password with custom Argon2id parameters
 * 
 * @param password Input password
 * @param password_len Length of password
 * @param t_cost Time cost (3-10 recommended)
 * @param m_cost Memory cost in KiB (65536-1048576 recommended)
 * @param parallelism Thread count (1-4 recommended)
 * @param hash_out Output buffer for encoded hash (256 bytes minimum)
 * @param hash_out_len Size of output buffer
 * @return 0 on success, negative on error
 * 
 * @validation Parameters validated for reasonable ranges
 */
NEXTSSL_BASE_API int nextssl_base_pow_argon2id_hash_custom(
    const uint8_t *password, size_t password_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    char *hash_out, size_t hash_out_len);

/**
 * Verify password against Argon2id hash
 * 
 * @param password Input password to verify
 * @param password_len Length of password
 * @param hash_encoded Encoded hash from hash() function
 * @return 1 if match, 0 if mismatch, negative on error
 * 
 * @security Constant-time comparison
 */
NEXTSSL_BASE_API int nextssl_base_pow_argon2id_verify(
    const uint8_t *password, size_t password_len,
    const char *hash_encoded);

/* ========== scrypt ========== */

/**
 * Hash password with scrypt (recommended defaults)
 * 
 * @param password Input password
 * @param password_len Length of password
 * @param hash_out Output buffer for hash (64 bytes)
 * @param salt_out Output buffer for salt (32 bytes, generated automatically)
 * @return 0 on success, negative on error
 * 
 * @note Uses N=65536, r=8, p=1 (OWASP 2023)
 * @compliance RFC 7914
 */
NEXTSSL_BASE_API int nextssl_base_pow_scrypt_hash(
    const uint8_t *password, size_t password_len,
    uint8_t hash_out[64],
    uint8_t salt_out[32]);

/**
 * Verify password against scrypt hash
 * 
 * @param password Input password
 * @param password_len Length of password
 * @param expected_hash Expected hash
 * @param salt Salt used during hashing
 * @return 1 if match, 0 if mismatch, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_pow_scrypt_verify(
    const uint8_t *password, size_t password_len,
    const uint8_t expected_hash[64],
    const uint8_t salt[32]);

/* ========== bcrypt ========== */

/**
 * Hash password with bcrypt (legacy support)
 * 
 * @param password Input password (max 72 bytes)
 * @param password_len Length of password
 * @param cost Cost parameter (10-15, default 12)
 * @param hash_out Output buffer for encoded hash (64 bytes minimum)
 * @param hash_out_len Size of output buffer
 * @return 0 on success, negative on error
 * 
 * @warning Truncates passwords >72 bytes, consider Argon2id instead
 * @note Cost 12 = 4096 rounds (2023 recommendation)
 */
NEXTSSL_BASE_API int nextssl_base_pow_bcrypt_hash(
    const uint8_t *password, size_t password_len,
    uint8_t cost,
    char *hash_out, size_t hash_out_len);

/**
 * Verify password against bcrypt hash
 * 
 * @param password Input password
 * @param password_len Length of password
 * @param hash_encoded Encoded bcrypt hash
 * @return 1 if match, 0 if mismatch, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_pow_bcrypt_verify(
    const uint8_t *password, size_t password_len,
    const char *hash_encoded);

/**
 * Self-test for PoW operations
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_BASE_API int nextssl_base_pow_selftest(void);

#endif /* NEXTSSL_BASE_POW_H */
