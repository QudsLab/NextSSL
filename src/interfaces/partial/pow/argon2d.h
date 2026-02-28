/**
 * @file argon2d.h
 * @brief Argon2d (data-dependent variant) password hashing interface
 * @layer partial
 * @category pow
 * @visibility hidden
 * 
 * Argon2d variant - data-dependent memory access patterns, maximum resistance
 * to GPU/ASIC attacks. Use for cryptocurrency PoW where side-channel attacks
 * are not a concern.
 * 
 * @warning Vulnerable to side-channel attacks. Do NOT use for password hashing.
 * @compliance RFC 9106, PHC Winner 2015
 */

#ifndef NEXTSSL_PARTIAL_POW_ARGON2D_H
#define NEXTSSL_PARTIAL_POW_ARGON2D_H

#include "../../visibility.h"
#include <stddef.h>
#include <stdint.h>

/**
 * Hash with Argon2d (data-dependent variant)
 * 
 * @param password Input password
 * @param password_len Length of password in bytes
 * @param salt Cryptographic salt (16+ bytes recommended)
 * @param salt_len Length of salt
 * @param t_cost Time cost (iterations), 3+ recommended
 * @param m_cost Memory cost in KiB, 65536+ recommended
 * @param parallelism Degree of parallelism, 1-4 typical
 * @param hash_len Output hash length (16-64 bytes typical)
 * @param out Output buffer for hash
 * @return 0 on success, negative on error
 * 
 * @security Maximum GPU/ASIC resistance, vulnerable to side-channels
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_argon2d_hash(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    size_t hash_len, uint8_t *out);

/**
 * Verify against Argon2d hash
 * 
 * @param password Input password to verify
 * @param password_len Length of password
 * @param encoded_hash PHC string format hash (e.g., "$argon2d$v=19$...")
 * @return 1 if match, 0 if mismatch, negative on error
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_argon2d_verify(
    const uint8_t *password, size_t password_len,
    const char *encoded_hash);

/**
 * Encode Argon2d hash to PHC string format
 * 
 * @param t_cost Time cost parameter
 * @param m_cost Memory cost in KiB
 * @param parallelism Parallelism parameter
 * @param salt Salt bytes
 * @param salt_len Salt length
 * @param hash Hash bytes
 * @param hash_len Hash length
 * @param encoded Output buffer for PHC string (256+ bytes)
 * @param encoded_len Size of output buffer
 * @return 0 on success, negative on error
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_argon2d_encode(
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *hash, size_t hash_len,
    char *encoded, size_t encoded_len);

/**
 * Self-test for Argon2d implementation
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_argon2d_selftest(void);

#endif /* NEXTSSL_PARTIAL_POW_ARGON2D_H */
