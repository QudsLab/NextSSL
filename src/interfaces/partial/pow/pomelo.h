/**
 * @file pomelo.h
 * @brief Pomelo password hashing function interface
 * @layer partial
 * @category pow
 * @visibility hidden
 * 
 * Pomelo - memory-hard password hashing optimized for parallelism.
 * Designed for server-side password hashing with fine-grained parallelism.
 * 
 * @compliance PHC Finalist 2015
 */

#ifndef NEXTSSL_PARTIAL_POW_POMELO_H
#define NEXTSSL_PARTIAL_POW_POMELO_H

#include "../../visibility.h"
#include <stddef.h>
#include <stdint.h>

/**
 * Hash password with Pomelo
 * 
 * @param password Input password
 * @param password_len Length of password
 * @param salt Salt (16+ bytes recommended)
 * @param salt_len Length of salt
 * @param t_cost Time cost parameter, 1-3 typical
 * @param m_cost Memory cost in KiB, 32768+ typical
 * @param parallelism Number of threads, 1-8 typical
 * @param hash_len Output hash length
 * @param out Output buffer for hash
 * @return 0 on success, negative on error
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_pomelo_hash(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    size_t hash_len, uint8_t *out);

/**
 * Verify password against Pomelo hash (constant-time)
 * 
 * @param password Input password to verify
 * @param password_len Length of password
 * @param salt Salt used during hashing
 * @param salt_len Length of salt
 * @param t_cost Time cost used
 * @param m_cost Memory cost used
 * @param parallelism Parallelism used
 * @param expected_hash Expected hash to compare
 * @param hash_len Length of hash
 * @return 1 if match, 0 if mismatch, negative on error
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_pomelo_verify(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    const uint8_t *expected_hash, size_t hash_len);

/**
 * Self-test for Pomelo implementation
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_pomelo_selftest(void);

#endif /* NEXTSSL_PARTIAL_POW_POMELO_H */
