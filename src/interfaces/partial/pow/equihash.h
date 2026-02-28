/**
 * @file equihash.h
 * @brief Equihash proof-of-work algorithm interface
 * @layer partial
 * @category pow
 * @visibility hidden
 * 
 * Equihash - memory-hard PoW based on generalized birthday problem.
 * Used in Zcash, Bitcoin Gold. ASIC-resistant due to memory requirements.
 * 
 * @note Primarily for cryptocurrency PoW, not password hashing
 */

#ifndef NEXTSSL_PARTIAL_POW_EQUIHASH_H
#define NEXTSSL_PARTIAL_POW_EQUIHASH_H

#include "../../visibility.h"
#include <stddef.h>
#include <stdint.h>

/**
 * Compute Equihash solution
 * 
 * @param input Input data (block header etc.)
 * @param input_len Length of input
 * @param n Parameter n (e.g., 200 for Zcash)
 * @param k Parameter k (e.g., 9 for Zcash)
 * @param solution Output buffer for solution
 * @param solution_len Size of solution buffer
 * @return 0 on success (solution found), negative on error
 * 
 * @note This is a solver - may take significant time/memory
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_equihash_solve(
    const uint8_t *input, size_t input_len,
    uint32_t n, uint32_t k,
    uint8_t *solution, size_t solution_len);

/**
 * Verify Equihash solution
 * 
 * @param input Input data
 * @param input_len Length of input
 * @param n Parameter n
 * @param k Parameter k
 * @param solution Solution to verify
 * @param solution_len Length of solution
 * @return 1 if valid, 0 if invalid, negative on error
 * 
 * @note Verification is fast compared to solving
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_equihash_verify(
    const uint8_t *input, size_t input_len,
    uint32_t n, uint32_t k,
    const uint8_t *solution, size_t solution_len);

/**
 * Self-test for Equihash implementation
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_equihash_selftest(void);

#endif /* NEXTSSL_PARTIAL_POW_EQUIHASH_H */
