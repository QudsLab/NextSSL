/**
 * @file argon2i.h
 * @brief Argon2i (data-independent variant) password hashing interface
 * @layer partial
 * @category pow
 * @visibility hidden
 * 
 * Argon2i variant - data-independent memory access patterns, resistant to
 * side-channel attacks. Use for password hashing where adversary may observe
 * memory access patterns (e.g., multi-tenant environments).
 * 
 * @warning Slower than Argon2id. Use Argon2id unless side-channel resistance required.
 * @compliance RFC 9106, PHC Winner 2015
 */

#ifndef NEXTSSL_PARTIAL_POW_ARGON2I_H
#define NEXTSSL_PARTIAL_POW_ARGON2I_H

#include "../../visibility.h"
#include <stddef.h>
#include <stdint.h>

/**
 * Hash password with Argon2i (data-independent variant)
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
 * @security Side-channel resistant, slower than Argon2id
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_argon2i_hash(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    size_t hash_len, uint8_t *out);

/**
 * Verify password against Argon2i hash
 * 
 * @param password Input password to verify
 * @param password_len Length of password
 * @param encoded_hash PHC string format hash (e.g., "$argon2i$v=19$...")
 * @return 1 if match, 0 if mismatch, negative on error
 * 
 * @note Constant-time comparison used internally
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_argon2i_verify(
    const uint8_t *password, size_t password_len,
    const char *encoded_hash);

/**
 * Encode Argon2i hash to PHC string format
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
NEXTSSL_PARTIAL_API int nextssl_partial_pow_argon2i_encode(
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *hash, size_t hash_len,
    char *encoded, size_t encoded_len);

/**
 * Self-test for Argon2i implementation
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_argon2i_selftest(void);

#endif /* NEXTSSL_PARTIAL_POW_ARGON2I_H */
