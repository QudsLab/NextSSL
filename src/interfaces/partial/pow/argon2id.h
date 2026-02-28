/**
 * @file argon2id.h
 * @brief Layer 1 (Partial) - Argon2id Password Hashing Interface
 * 
 * @visibility HIDDEN (NEXTSSL_PARTIAL_API)
 * @layer 1
 * @category pow
 * @subcategory argon2id
 * 
 * Argon2id - Hybrid variant (recommended for password hashing).
 * Winner of Password Hashing Competition (PHC) 2015, RFC 9106.
 * 
 * @warning Use this for password storage, NOT for key derivation (use kdf.h)
 * @warning Memory cost MUST be >= 64 MiB for production use
 * 
 * Thread safety: Thread-safe (stateless operations).
 */

#ifndef NEXTSSL_PARTIAL_POW_ARGON2ID_H
#define NEXTSSL_PARTIAL_POW_ARGON2ID_H

#include <stddef.h>
#include <stdint.h>
#include "../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NEXTSSL_ARGON2ID_SALTLEN_MIN     16
#define NEXTSSL_ARGON2ID_HASHLEN_MIN     16
#define NEXTSSL_ARGON2ID_HASHLEN_MAX     4294967295U

/**
 * @brief Hash password using Argon2id
 * 
 * @param time_cost Time cost (iterations, min 3 for passwords)
 * @param memory_cost Memory cost in KiB (min 65536 = 64 MiB)
 * @param parallelism Degree of parallelism (1-4 typical)
 * @param password Password to hash
 * @param password_len Password length
 * @param salt Random salt (min 16 bytes)
 * @param salt_len Salt length
 * @param hash_output Output buffer for hash
 * @param hash_len Desired hash length (32 bytes typical)
 * @return 0 on success, negative on error
 * 
 * OWASP 2023 recommendations:
 * - time_cost: 3-5
 * - memory_cost: 65536 KiB (64 MiB) minimum, 524288 (512 MiB) preferred
 * - parallelism: 1 or 4
 * - hash_len: 32 bytes
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_pow_argon2id_hash(
    uint32_t time_cost,
    uint32_t memory_cost,
    uint32_t parallelism,
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    uint8_t *hash_output,
    size_t hash_len
);

/**
 * @brief Verify password against Argon2id hash
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_pow_argon2id_verify(
    const uint8_t *hash,
    size_t hash_len,
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    uint32_t time_cost,
    uint32_t memory_cost,
    uint32_t parallelism
);

/**
 * @brief Encode Argon2id hash to PHC string format
 * 
 * Format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_pow_argon2id_encode(
    char *encoded,
    size_t encoded_len,
    const uint8_t *hash,
    size_t hash_len,
    const uint8_t *salt,
    size_t salt_len,
    uint32_t time_cost,
    uint32_t memory_cost,
    uint32_t parallelism
);

NEXTSSL_PARTIAL_API int
nextssl_partial_pow_argon2id_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_POW_ARGON2ID_H */
