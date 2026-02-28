/**
 * @file bcrypt.h
 * @brief Layer 1 (Partial) - bcrypt Password Hashing Interface
 * 
 * @visibility HIDDEN (NEXTSSL_PARTIAL_API)
 * @layer 1
 * @category pow
 * @subcategory bcrypt
 * 
 * bcrypt - Blowfish-based password hashing (Niels Provos, 1999).
 * Widely deployed but less memory-hard than scrypt/Argon2.
 * 
 * @warning Prefer Argon2id for new applications
 * @warning bcrypt limited to 72-byte passwords (truncates beyond)
 * @warning Use for compatibility with existing bcrypt hashes
 * 
 * Thread safety: Thread-safe (stateless operations).
 */

#ifndef NEXTSSL_PARTIAL_POW_BCRYPT_H
#define NEXTSSL_PARTIAL_POW_BCRYPT_H

#include <stddef.h>
#include <stdint.h>
#include "../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NEXTSSL_BCRYPT_HASHSIZE 24
#define NEXTSSL_BCRYPT_SALTSIZE 16

/**
 * @brief Hash password using bcrypt
 * 
 * @param password Password (max 72 bytes, truncated beyond)
 * @param password_len Password length
 * @param salt Random salt (16 bytes)
 * @param cost Cost factor (4-31, 12 recommended for 2023)
 * @param hash Output hash (24 bytes)
 * @return 0 on success, negative on error
 * 
 * Cost recommendations:
 * - 2023: cost = 12 (4096 rounds)
 * - Future: Increase by 1 every ~2 years
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_pow_bcrypt_hash(
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    uint32_t cost,
    uint8_t *hash
);

NEXTSSL_PARTIAL_API int
nextssl_partial_pow_bcrypt_verify(
    const uint8_t *password,
    size_t password_len,
    const uint8_t *hash
);

NEXTSSL_PARTIAL_API int
nextssl_partial_pow_bcrypt_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_POW_BCRYPT_H */
