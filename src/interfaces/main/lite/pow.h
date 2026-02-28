/**
 * @file pow_lite.h
 * @brief Lite variant Proof-of-Work API (SHA-256 based only)
 * @version 0.1.0-beta-lite
 * @date 2026-02-28
 */

#ifndef NEXTSSL_MAIN_LITE_POW_H
#define NEXTSSL_MAIN_LITE_POW_H

#include "../../../config.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief PoW challenge structure
 */
typedef struct {
    uint8_t challenge[32];     /**< Challenge bytes */
    uint32_t difficulty;       /**< Difficulty (leading zero bits) */
    uint64_t timestamp;        /**< Challenge creation time */
} nextssl_lite_pow_challenge_t;

/**
 * @brief PoW solution structure
 */
typedef struct {
    uint8_t nonce[32];         /**< Nonce that solves the challenge */
    uint8_t hash[32];          /**< Resulting hash */
    uint64_t iterations;       /**< Iterations tried */
} nextssl_lite_pow_solution_t;

/**
 * @brief Generate PoW challenge (server-side)
 * 
 * @param difficulty Difficulty level (leading zero bits, e.g., 20)
 * @param challenge Output challenge structure
 * @return 0 on success
 */
NEXTSSL_API int nextssl_lite_pow_generate_challenge(
    uint32_t difficulty,
    nextssl_lite_pow_challenge_t *challenge
);

/**
 * @brief Solve PoW challenge (client-side)
 * 
 * Finds a nonce such that SHA-256(challenge || nonce) has 'difficulty' leading zero bits
 * 
 * @param challenge Challenge to solve
 * @param solution Output solution
 * @param timeout_seconds Max time to search (0 = no limit)
 * @return 0 on success, negative on timeout or error
 * 
 * @retval 0 Solution found
 * @retval -NEXTSSL_ERROR_TIMEOUT Timeout reached before solution found
 */
NEXTSSL_API int nextssl_lite_pow_solve(
    const nextssl_lite_pow_challenge_t *challenge,
    nextssl_lite_pow_solution_t *solution,
    uint32_t timeout_seconds
);

/**
 * @brief Verify PoW solution (server-side)
 * 
 * @param challenge Original challenge
 * @param solution Proposed solution
 * @return 0 if valid, negative if invalid
 * 
 * @retval 0 Solution is valid
 * @retval -NEXTSSL_ERROR_INVALID_SOLUTION Solution does not meet difficulty
 * @retval -NEXTSSL_ERROR_EXPIRED Challenge has expired
 */
NEXTSSL_API int nextssl_lite_pow_verify(
    const nextssl_lite_pow_challenge_t *challenge,
    const nextssl_lite_pow_solution_t *solution
);

/**
 * @brief Estimate time to solve challenge
 * 
 * @param difficulty Difficulty level
 * @return Estimated seconds to solve (approximate)
 */
NEXTSSL_API uint64_t nextssl_lite_pow_estimate_time(uint32_t difficulty);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_MAIN_LITE_POW_H */
