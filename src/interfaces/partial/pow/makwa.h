/**
 * @file makwa.h
 * @brief Makwa password hashing function interface
 * @layer partial
 * @category pow
 * @visibility hidden
 * 
 * Makwa - delegation-friendly password hashing based on modular squaring.
 * Allows offloading work verification to untrusted servers. PHC finalist.
 * 
 * @compliance PHC Finalist 2015
 */

#ifndef NEXTSSL_PARTIAL_POW_MAKWA_H
#define NEXTSSL_PARTIAL_POW_MAKWA_H

#include "../../visibility.h"
#include <stddef.h>
#include <stdint.h>

/**
 * Hash password with Makwa
 * 
 * @param password Input password
 * @param password_len Length of password
 * @param salt Salt (16+ bytes recommended)
 * @param salt_len Length of salt
 * @param work_factor Work factor (log2 of squarings), 10-15 typical
 * @param hash_len Output hash length
 * @param out Output buffer for hash
 * @return 0 on success, negative on error
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_makwa_hash(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t work_factor,
    size_t hash_len, uint8_t *out);

/**
 * Verify password against Makwa hash (constant-time)
 * 
 * @param password Input password to verify
 * @param password_len Length of password
 * @param salt Salt used during hashing
 * @param salt_len Length of salt
 * @param work_factor Work factor used
 * @param expected_hash Expected hash to compare
 * @param hash_len Length of hash
 * @return 1 if match, 0 if mismatch, negative on error
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_makwa_verify(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t work_factor,
    const uint8_t *expected_hash, size_t hash_len);

/**
 * Self-test for Makwa implementation
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_makwa_selftest(void);

#endif /* NEXTSSL_PARTIAL_POW_MAKWA_H */
