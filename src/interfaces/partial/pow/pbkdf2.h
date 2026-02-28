/**
 * @file pbkdf2.h
 * @brief PBKDF2 (Password-Based Key Derivation Function 2) interface
 * @layer partial
 * @category pow
 * @visibility hidden
 * 
 * PBKDF2 - widely deployed password-based KDF, standardized in PKCS#5.
 * Applies PRF (HMAC) iteratively to derive keys from passwords.
 * 
 * @warning Not memory-hard. Vulnerable to GPU/ASIC attacks. Consider Argon2id.
 * @compliance RFC 8018 (PKCS #5 v2.1), NIST SP 800-132
 */

#ifndef NEXTSSL_PARTIAL_POW_PBKDF2_H
#define NEXTSSL_PARTIAL_POW_PBKDF2_H

#include "../../visibility.h"
#include <stddef.h>
#include <stdint.h>

/**
 * PBKDF2 with HMAC-SHA256
 * 
 * @param password Input password
 * @param password_len Length of password
 * @param salt Salt (16+ bytes recommended)
 * @param salt_len Length of salt
 * @param iterations Iteration count (600,000+ for 2023, OWASP recommendation)
 * @param dklen Derived key length in bytes
 * @param out Output buffer for derived key
 * @return 0 on success, negative on error
 * 
 * @security Not memory-hard. Use Argon2id for new applications.
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_pbkdf2_sha256(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    size_t dklen, uint8_t *out);

/**
 * PBKDF2 with HMAC-SHA512
 * 
 * @param password Input password
 * @param password_len Length of password
 * @param salt Salt (16+ bytes recommended)
 * @param salt_len Length of salt
 * @param iterations Iteration count (210,000+ for 2023)
 * @param dklen Derived key length in bytes
 * @param out Output buffer for derived key
 * @return 0 on success, negative on error
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_pbkdf2_sha512(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    size_t dklen, uint8_t *out);

/**
 * Verify password against PBKDF2 hash (constant-time)
 * 
 * @param password Input password to verify
 * @param password_len Length of password
 * @param salt Salt used during hashing
 * @param salt_len Length of salt
 * @param iterations Iteration count used
 * @param expected_hash Expected hash to compare against
 * @param hash_len Length of hash
 * @param use_sha512 If 1, use SHA-512; if 0, use SHA-256
 * @return 1 if match, 0 if mismatch, negative on error
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_pbkdf2_verify(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    const uint8_t *expected_hash, size_t hash_len,
    int use_sha512);

/**
 * Self-test for PBKDF2 implementation
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_pbkdf2_selftest(void);

#endif /* NEXTSSL_PARTIAL_POW_PBKDF2_H */
