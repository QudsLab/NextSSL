/**
 * @file pow.c
 * @brief Lite variant Proof-of-Work implementation (SHA-256 based)
 */

#include "pow.h"
#include "../../../primitives/hash/fast/sha256/sha256.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>

// Generate random challenge
int nextssl_lite_pow_generate_challenge(
    uint32_t difficulty,
    nextssl_lite_pow_challenge_t *challenge
) {
    if (!challenge) {
        return -1;  // NEXTSSL_ERROR_INVALID_PARAMETER
    }
    
    challenge->difficulty = difficulty;
    challenge->timestamp = (uint64_t)time(NULL);
    
    // Generate random challenge data (in production, use CSPRNG)
    for (int i = 0; i < 32; i++) {
        challenge->challenge[i] = (uint8_t)(rand() & 0xFF);
    }
    
    return 0;
}

// Solve PoW challenge (find nonce such that hash has required leading zeros)
int nextssl_lite_pow_solve(
    const nextssl_lite_pow_challenge_t *challenge,
    nextssl_lite_pow_solution_t *solution,
    uint32_t timeout_seconds
) {
    if (!challenge || !solution) {
        return -1;
    }
    
    uint8_t hash[32];
    uint64_t iterations = 0;
    uint32_t required_zeros = challenge->difficulty;
    time_t start_time = time(NULL);
    
    memset(solution->nonce, 0, 32);
    solution->iterations = 0;
    
    // Brute force search for valid nonce
    while (1) {
        // Check timeout
        if (timeout_seconds > 0) {
            if ((uint64_t)(time(NULL) - start_time) >= timeout_seconds) {
                return -6;  // NEXTSSL_ERROR_TIMEOUT
            }
        }
        
        // Hash challenge + nonce
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, challenge->challenge, 32);
        sha256_update(&ctx, solution->nonce, 32);
        sha256_final(&ctx, hash);
        
        // Check if hash meets difficulty (leading zeros in bits)
        int valid = 1;
        uint32_t bits_needed = required_zeros;
        
        for (size_t i = 0; i < 32 && bits_needed > 0; i++) {
            uint8_t byte = hash[i];
            
            if (bits_needed >= 8) {
                // Need full byte of zeros
                if (byte != 0) {
                    valid = 0;
                    break;
                }
                bits_needed -= 8;
            } else {
                // Need partial byte of zeros (check leading bits)
                uint8_t mask = (uint8_t)(0xFF << (8 - bits_needed));
                if ((byte & mask) != 0) {
                    valid = 0;
                    break;
                }
                bits_needed = 0;
            }
        }
        
        iterations++;
        
        if (valid) {
            // Found valid solution
            memcpy(solution->hash, hash, 32);
            solution->iterations = iterations;
            return 0;  // Success
        }
        
        // Increment nonce (treat as big-endian counter)
        for (int i = 31; i >= 0; i--) {
            solution->nonce[i]++;
            if (solution->nonce[i] != 0) break;  // No carry
        }
    }
    
    return -6;  // NEXTSSL_ERROR_POW_NOT_FOUND
}

// Verify PoW solution
int nextssl_lite_pow_verify(
    const nextssl_lite_pow_challenge_t *challenge,
    const nextssl_lite_pow_solution_t *solution
) {
    if (!challenge || !solution) {
        return -1;
    }
    
    uint8_t hash[32];
    
    // Recompute hash
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, challenge->challenge, 32);
    sha256_update(&ctx, solution->nonce, 32);
    sha256_final(&ctx, hash);
    
    // Verify hash matches
    if (memcmp(hash, solution->hash, 32) != 0) {
        return -5;  // NEXTSSL_ERROR_AUTH_FAIL (hash mismatch)
    }
    
    // Verify difficulty
    uint32_t bits_needed = challenge->difficulty;
    for (size_t i = 0; i < 32 && bits_needed > 0; i++) {
        uint8_t byte = hash[i];
        
        if (bits_needed >= 8) {
            if (byte != 0) {
                return -5;  // Doesn't meet difficulty
            }
            bits_needed -= 8;
        } else {
            uint8_t mask = (uint8_t)(0xFF << (8 - bits_needed));
            if ((byte & mask) != 0) {
                return -5;  // Doesn't meet difficulty
            }
            bits_needed = 0;
        }
    }
    
    return 0;  // Valid
}

// Estimate time to solve
uint64_t nextssl_lite_pow_estimate_time(uint32_t difficulty) {
    // Rough estimate: 2^difficulty hashes needed
    // Assuming ~1M hashes/sec on average CPU
    uint64_t hashes = 1ULL << difficulty;
    uint64_t hashes_per_sec = 1000000;  // 1M hashes/sec estimate
    
    return hashes / hashes_per_sec;  // Time in seconds
}
