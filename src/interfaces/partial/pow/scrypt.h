/**
 * @file scrypt.h
 * @brief Layer 1 (Partial) - scrypt Password Hashing Interface
 * 
 * @visibility HIDDEN (NEXTSSL_PARTIAL_API)
 * @layer 1
 * @category pow
 * @subcategory scrypt
 * 
 * scrypt - Memory-hard password hashing function (RFC 7914).
 * Older than Argon2, but still widely used (Bitcoin, Litecoin).
 * 
 * @warning Prefer Argon2id for new applications
 * @warning Use for compatibility with existing scrypt hashes only
 * 
 * Thread safety: Thread-safe (stateless operations).
 */

#ifndef NEXTSSL_PARTIAL_POW_SCRYPT_H
#define NEXTSSL_PARTIAL_POW_SCRYPT_H

#include <stddef.h>
#include <stdint.h>
#include "../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Hash password using scrypt
 * 
 * @param password Password to hash
 * @param password_len Password length
 * @param salt Random salt
 * @param salt_len Salt length  
 * @param N CPU/memory cost (power of 2, e.g., 32768)
 * @param r Block size (e.g., 8)
 * @param p Parallelization (e.g., 1)
 * @param dk Derived key output
 * @param dkLen Derived key length
 * @return 0 on success, negative on error
 * 
 * Recommended parameters (2023):
 * - N: 32768 (2^15) minimum, 65536 (2^16) preferred
 * - r: 8
 * - p: 1
 * - Memory usage: 128 * N * r * p bytes
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_pow_scrypt(
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    uint64_t N,
    uint32_t r,
    uint32_t p,
    uint8_t *dk,
    size_t dkLen
);

NEXTSSL_PARTIAL_API int
nextssl_partial_pow_scrypt_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_POW_SCRYPT_H */
