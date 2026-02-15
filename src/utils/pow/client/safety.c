#include "pow_client.h"

PoWError pow_client_check_safety(const PoWChallenge *c) {
    if (!c) return POW_ERR_INVALID_FORMAT;

    // 1. Algo Whitelist
    switch (c->algo) {
        case POW_ALGO_BLAKE3:
        case POW_ALGO_SHA256:
        case POW_ALGO_SHA3_256:
        case POW_ALGO_ARGON2ID:
            break; // Allowed
        case POW_ALGO_MD5:
        case POW_ALGO_SHA1:
            // Legacy disabled by default in strict mode
            return POW_ERR_SAFETY_VIOLATION;
        default:
            return POW_ERR_UNKNOWN_ALGO;
    }

    // 2. Batch Limits
    if (c->num_inputs > CLIENT_MAX_BATCH) {
        return POW_ERR_SAFETY_VIOLATION;
    }
    if (c->num_inputs > POW_MAX_INPUTS) {
        return POW_ERR_INVALID_FORMAT;
    }

    // 3. Memory Limits (Argon2)
    if (c->algo == POW_ALGO_ARGON2ID) {
        uint32_t mem_kb = c->argon2_m_cost_kb > 0 ? c->argon2_m_cost_kb : c->max_memory_kb;
        if (mem_kb > CLIENT_MAX_MEMORY_KB) {
            return POW_ERR_SAFETY_VIOLATION;
        }
    }

    // 4. Target Count
    if (c->num_targets > POW_MAX_TARGETS) {
        return POW_ERR_SAFETY_VIOLATION;
    }
    
    // 5. Complexity / Search Space Sanity Check
    // If we have ranges, check if space is > 0.
    if (c->num_ranges > 0) {
        uint64_t space_size = 0;
        for (uint32_t i = 0; i < c->num_ranges; i++) {
            if (c->ranges[i].max_char >= c->ranges[i].min_char) {
                space_size += (c->ranges[i].max_char - c->ranges[i].min_char + 1);
            }
        }
        if (space_size == 0) return POW_ERR_INVALID_FORMAT;
        
        // If Difficulty is high but space is small?
        // E.g. space = 10 (0-9), difficulty requires prefix "0000" (16 bits => 65536 tries expected)
        // 10 < 65536. Impossible to solve with high probability.
        // We can reject this.
        // Simplified check:
        // Expected Tries ~ 2^(difficulty_bits).
        // Max Tries possible with len L nonce = space^L.
        // Since we don't know nonce length limit here (it's up to solver), we skip this for now.
        // But if max_tries is set by server, we check against our limit.
    }

    return POW_OK;
}
