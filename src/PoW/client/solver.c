#include "solver.h"
#include "../core/pow_parser.h"
#include "../core/pow_difficulty.h"
#include "timer.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

// Forward declaration of the adapter getter (will be linked from adapters/dispatcher.c)
extern POWAlgoAdapter* pow_adapter_get(const char* algorithm_id);

int pow_client_parse_challenge(
    const char* challenge_base64,
    POWChallenge* out_challenge
) {
    if (!challenge_base64 || !out_challenge) return -1;
    
    if (pow_parser_decode_challenge(challenge_base64, out_challenge) != 0) return -2;
    
    if (out_challenge->version != 1) return -3;
    
    // Check if we have an adapter for this algorithm
    if (!pow_adapter_get(out_challenge->algorithm_id)) return -4;
    
    return 0;
}

int pow_client_solve(
    POWChallenge* challenge,
    POWSolution* out_solution
) {
    if (!challenge || !out_solution) return -1;
    
    POWAlgoAdapter* adapter = pow_adapter_get(challenge->algorithm_id);
    if (!adapter) return -4;
    
    // Start timer
    uint64_t start_time = pow_timer_start();
    
    uint64_t nonce = 0;
    // Context + Nonce (8 bytes)
    // Ensure buffer is large enough for context + nonce
    if (challenge->context_len > 256) return -5; // Sanity check
    
    uint8_t input[300]; 
    memcpy(input, challenge->context, challenge->context_len);
    
    uint8_t hash_output[64];
    bool found = false;
    
    // Main solver loop
    char nonce_str[32];
    for (nonce = 0; nonce < UINT64_MAX; nonce++) {
        // Append nonce as string (1, 2, ... 10)
        // User request: "allow the pow to only add as str some numarical values like 1 2 ...9, 10"
        // This implies appending the ASCII representation of the nonce.
        int nonce_len = sprintf(nonce_str, "%llu", (unsigned long long)nonce);
        
        // Ensure buffer is large enough
        if (challenge->context_len + nonce_len > sizeof(input)) return -5;
        
        memcpy(input + challenge->context_len, nonce_str, nonce_len);
        
        // Hash with optional parameters (e.g. Argon2 params)
        if (adapter->hash(input, challenge->context_len + nonce_len, challenge->algo_params, hash_output) != 0) {
            return -3;
        }
        
        // Check difficulty
        if (pow_difficulty_check(hash_output, challenge->target, challenge->target_len)) {
            found = true;
            break;
        }
        
        // Optional: Check time limits periodically here if needed
    }
    
    if (!found) return -2;
    
    double time_spent = pow_timer_stop(start_time);
    
    // Fill solution
    memset(out_solution, 0, sizeof(POWSolution));
    memcpy(out_solution->challenge_id, challenge->challenge_id, 16);
    out_solution->nonce = nonce;
    
    // Copy hash output (ensure we don't overflow if target_len > 64, though likely not)
    size_t hash_len = challenge->target_len > 64 ? 64 : challenge->target_len;
    memcpy(out_solution->hash_output, hash_output, hash_len);
    out_solution->hash_output_len = hash_len;
    
    out_solution->solve_time_seconds = time_spent;
    out_solution->attempts = nonce + 1;
    
    return 0;
}
