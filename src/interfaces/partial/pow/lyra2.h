/**
 * @file lyra2.h
 * @brief Lyra2 password hashing function interface
 * @layer partial
 * @category pow
 * @visibility hidden
 * 
 * Lyra2 - memory-hard password hashing with sponge construction.
 * PHC finalist, basis for Lyra2REv2 cryptocurrency PoW.
 * 
 * @compliance PHC Finalist 2015
 */

#ifndef NEXTSSL_PARTIAL_POW_LYRA2_H
#define NEXTSSL_PARTIAL_POW_LYRA2_H

#include "../../visibility.h"
#include <stddef.h>
#include <stdint.h>

/**
 * Hash password with Lyra2
 * 
 * @param password Input password
 * @param password_len Length of password
 * @param salt Salt (16+ bytes recommended)
 * @param salt_len Length of salt
 * @param t_cost Time cost parameter, 1-4 typical
 * @param m_cost Memory cost (number of rows), 4096+ typical
 * @param parallelism Number of parallel lanes, 1-4 typical
 * @param hash_len Output hash length
 * @param out Output buffer for hash
 * @return 0 on success, negative on error
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_lyra2_hash(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    size_t hash_len, uint8_t *out);

/**
 * Verify password against Lyra2 hash (constant-time)
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
NEXTSSL_PARTIAL_API int nextssl_partial_pow_lyra2_verify(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    const uint8_t *expected_hash, size_t hash_len);

/**
 * Self-test for Lyra2 implementation
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_lyra2_selftest(void);

#endif /* NEXTSSL_PARTIAL_POW_LYRA2_H */
