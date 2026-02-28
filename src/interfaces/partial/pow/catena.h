/**
 * @file catena.h
 * @brief Catena password hashing function interface
 * @layer partial
 * @category pow
 * @visibility hidden
 * 
 * Catena - memory-hard password hashing with provable sequential memory-hardness.
 * PHC finalist with formal security proofs.
 * 
 * @compliance PHC Finalist 2015
 */

#ifndef NEXTSSL_PARTIAL_POW_CATENA_H
#define NEXTSSL_PARTIAL_POW_CATENA_H

#include "../../visibility.h"
#include <stddef.h>
#include <stdint.h>

/**
 * Hash password with Catena
 * 
 * @param password Input password
 * @param password_len Length of password
 * @param salt Salt (16+ bytes recommended)
 * @param salt_len Length of salt
 * @param garlic Garlic parameter (memory cost exponent), 16-20 typical
 * @param lambda Lambda parameter (time cost), 2-4 typical
 * @param hash_len Output hash length
 * @param out Output buffer for hash
 * @return 0 on success, negative on error
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_catena_hash(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint8_t garlic, uint8_t lambda,
    size_t hash_len, uint8_t *out);

/**
 * Verify password against Catena hash (constant-time)
 * 
 * @param password Input password to verify
 * @param password_len Length of password
 * @param salt Salt used during hashing
 * @param salt_len Length of salt
 * @param garlic Garlic parameter used
 * @param lambda Lambda parameter used
 * @param expected_hash Expected hash to compare
 * @param hash_len Length of hash
 * @return 1 if match, 0 if mismatch, negative on error
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_catena_verify(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint8_t garlic, uint8_t lambda,
    const uint8_t *expected_hash, size_t hash_len);

/**
 * Self-test for Catena implementation
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_catena_selftest(void);

#endif /* NEXTSSL_PARTIAL_POW_CATENA_H */
