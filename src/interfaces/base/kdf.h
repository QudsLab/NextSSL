/**
 * @file kdf.h
 * @brief Layer 2: Key derivation function aggregation
 * @layer base
 * @category kdf
 * @visibility semi-public
 * 
 * Secure key derivation for expanding secrets into cryptographic keys.
 * 
 * **Functions provided:**
 * - HKDF (recommended, RFC 5869)
 * - Argon2id (password-based, memory-hard)
 * - PBKDF2 (legacy support)
 * 
 * @note For password hashing, prefer pow.h interfaces
 */

#ifndef NEXTSSL_BASE_KDF_H
#define NEXTSSL_BASE_KDF_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* ========== HKDF (RECOMMENDED) ========== */

/**
 * HKDF-SHA256 (recommended for key derivation)
 * 
 * @param ikm Input keying material
 * @param ikm_len Length of IKM
 * @param salt Optional salt (NULL if not used)
 * @param salt_len Length of salt
 * @param info Optional context info (NULL if not used)
 * @param info_len Length of info
 * @param okm Output keying material
 * @param okm_len Desired output length (max 8160 bytes)
 * @return 0 on success, negative on error
 * 
 * @compliance RFC 5869
 */
NEXTSSL_BASE_API int nextssl_base_kdf_hkdf_sha256(
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len);

/**
 * HKDF-SHA512 (high security variant)
 * 
 * @param ikm Input keying material
 * @param ikm_len Length of IKM
 * @param salt Optional salt
 * @param salt_len Length of salt
 * @param info Optional context info
 * @param info_len Length of info
 * @param okm Output keying material
 * @param okm_len Desired output length (max 16320 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_kdf_hkdf_sha512(
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len);

/* ========== Argon2id (password-based) ========== */

/**
 * Argon2id key derivation (password-based, memory-hard)
 * 
 * @param password Input password
 * @param password_len Length of password
 * @param salt Salt (16+ bytes)
 * @param salt_len Length of salt
 * @param t_cost Time cost (3-10)
 * @param m_cost Memory cost in KiB (65536-1048576)
 * @param parallelism Thread count (1-4)
 * @param output Output key material
 * @param output_len Desired output length
 * @return 0 on success, negative on error
 * 
 * @note For password hashing, use pow.h functions instead
 */
NEXTSSL_BASE_API int nextssl_base_kdf_argon2id(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    uint8_t *output, size_t output_len);

/* ========== PBKDF2 (legacy) ========== */

/**
 * PBKDF2-HMAC-SHA256 (legacy support)
 * 
 * @param password Input password
 * @param password_len Length of password
 * @param salt Salt
 * @param salt_len Length of salt
 * @param iterations Iteration count (600,000+ recommended)
 * @param output Output key material
 * @param output_len Desired output length
 * @return 0 on success, negative on error
 * 
 * @warning Not memory-hard, prefer HKDF or Argon2id
 * @compliance RFC 8018
 */
NEXTSSL_BASE_API int nextssl_base_kdf_pbkdf2_sha256(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    uint8_t *output, size_t output_len);

/**
 * Self-test for KDF operations
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_BASE_API int nextssl_base_kdf_selftest(void);

#endif /* NEXTSSL_BASE_KDF_H */
