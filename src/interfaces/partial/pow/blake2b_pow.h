/**
 * @file blake2b_pow.h
 * @brief BLAKE2b in password hashing mode (keyed hashing)
 * @layer partial
 * @category pow
 * @visibility hidden
 * 
 * BLAKE2b-based password hashing using keyed mode with salt.
 * Fast, but NOT memory-hard - suitable only where high iteration counts
 * compensate (e.g., constrained embedded systems).
 * 
 * @warning Not memory-hard. Prefer Argon2id or scrypt for password hashing.
 */

#ifndef NEXTSSL_PARTIAL_POW_BLAKE2B_POW_H
#define NEXTSSL_PARTIAL_POW_BLAKE2B_POW_H

#include "../../visibility.h"
#include <stddef.h>
#include <stdint.h>

/**
 * BLAKE2b password hashing with iterations
 * 
 * @param password Input password
 * @param password_len Length of password
 * @param salt Salt (16+ bytes recommended)
 * @param salt_len Length of salt
 * @param iterations Number of iterations (100,000+ recommended)
 * @param hash_len Output hash length (16-64 bytes)
 * @param out Output buffer for hash
 * @return 0 on success, negative on error
 * 
 * @note Fast but not memory-hard. Use only in resource-constrained scenarios.
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_blake2b_hash(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    size_t hash_len, uint8_t *out);

/**
 * Verify password against BLAKE2b hash (constant-time)
 * 
 * @param password Input password to verify
 * @param password_len Length of password
 * @param salt Salt used during hashing
 * @param salt_len Length of salt
 * @param iterations Iteration count used
 * @param expected_hash Expected hash to compare
 * @param hash_len Length of hash
 * @return 1 if match, 0 if mismatch, negative on error
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_blake2b_verify(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    const uint8_t *expected_hash, size_t hash_len);

/**
 * Self-test for BLAKE2b PoW implementation
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_blake2b_selftest(void);

#endif /* NEXTSSL_PARTIAL_POW_BLAKE2B_POW_H */
