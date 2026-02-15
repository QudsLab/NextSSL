#include "pow_server.h"
#include "complexity/calc_interface.h"
#include <string.h>
#include <stdlib.h>
#include <math.h>

// Reference Throughput (Ops/ms) - Calibrated for a "weak" client
#define REF_OPS_MS_BLAKE3 10000.0
#define REF_OPS_MS_ARGON2 0.5 
#define REF_OPS_MS_SHA256 5000.0

// External declarations for calculators (or include headers if preferred)
double pow_calc_cost_argon2(const PoWComplexityArgs *args);
double pow_calc_cost_sha(PoWAlgorithm algo, const PoWComplexityArgs *args);
double pow_calc_cost_blake(PoWAlgorithm algo, const PoWComplexityArgs *args);

double pow_calc_cost(PoWAlgorithm algo, const PoWComplexityArgs *args) {
    switch (algo) {
        case POW_ALGO_ARGON2ID: return pow_calc_cost_argon2(args);
        case POW_ALGO_SHA256:
        case POW_ALGO_SHA3_256:
        case POW_ALGO_MD5:
        case POW_ALGO_SHA1:     return pow_calc_cost_sha(algo, args);
        case POW_ALGO_BLAKE3:   return pow_calc_cost_blake(algo, args);
        default: return 1.0;
    }
}

int pow_server_init_challenge(PoWChallenge *c, PoWAlgorithm algo) {
    if (!c) return -1;
    memset(c, 0, sizeof(PoWChallenge));
    c->version = 2;
    c->algo = algo;
    return 0;
}

int pow_server_tune_difficulty(PoWChallenge *c, uint32_t target_time_ms) {
    if (!c || target_time_ms == 0) return -1;
    
    // 1. Prepare Complexity Args
    PoWComplexityArgs args;
    memset(&args, 0, sizeof(args));
    
    // Estimate average input length (e.g., input + nonce)
    size_t avg_input_len = 0;
    for(uint32_t i=0; i<c->num_inputs; i++) avg_input_len += c->input_lens[i];
    if (c->num_inputs > 0) avg_input_len /= c->num_inputs;
    
    args.input_len = avg_input_len + 16; // + Nonce size
    args.t_cost = c->argon2_t_cost;
    args.m_cost_kb = c->argon2_m_cost_kb;
    args.parallelism = c->argon2_parallelism;
    
    // 2. Calculate Cost per Hash
    double cost_per_hash = pow_calc_cost(c->algo, &args);
    if (cost_per_hash <= 0.0) cost_per_hash = 1.0;
    
    // 3. Determine Reference Throughput
    double ref_ops_ms = 1000.0;
    if (c->algo == POW_ALGO_ARGON2ID) ref_ops_ms = REF_OPS_MS_ARGON2;
    else if (c->algo == POW_ALGO_BLAKE3) ref_ops_ms = REF_OPS_MS_BLAKE3;
    else ref_ops_ms = REF_OPS_MS_SHA256;
    
    // 4. Calculate Required Attempts
    double total_ops_budget = ref_ops_ms * (double)target_time_ms;
    double target_attempts = total_ops_budget / cost_per_hash;
    
    if (target_attempts < 1.0) target_attempts = 1.0;
    
    // 5. Convert to Difficulty
    // D = log2(target_attempts)
    uint32_t difficulty_bits = 0;
    while ((1ULL << (difficulty_bits + 1)) <= target_attempts) {
        difficulty_bits++;
    }
    
    // Cap at reasonable limits
    if (difficulty_bits > 30) difficulty_bits = 30; 
    
    // Set Target (Prefix Zeroes)
    // For simplicity, we use byte-aligned prefix for now.
    // Ideally, we should use target_threshold for bit-level precision.
    
    uint32_t prefix_len = difficulty_bits / 8;
    if (prefix_len > POW_MAX_PREFIX_LEN) prefix_len = POW_MAX_PREFIX_LEN;
    
    uint8_t zeros[POW_MAX_PREFIX_LEN];
    memset(zeros, 0, sizeof(zeros));
    
    // Difficulty in iterations (if using simple matching) OR bit-mask
    // Here we set prefix_len bytes to 0.
    // And we set 'difficulty' field to 1 (meaning 1 match required).
    
    // Clear existing targets
    c->num_targets = 0;
    pow_server_add_target(c, zeros, prefix_len, 1);
    
    // Store expected ops for verification/logging
    c->max_tries = (uint64_t)target_attempts * 2; // Allow some buffer
    
    return 0;
}

int pow_server_add_input(PoWChallenge *c, const uint8_t *data, size_t len) {
    if (!c || c->num_inputs >= POW_MAX_INPUTS) return -1;
    c->inputs[c->num_inputs] = (uint8_t*)malloc(len);
    if (!c->inputs[c->num_inputs]) return -1;
    memcpy(c->inputs[c->num_inputs], data, len);
    c->input_lens[c->num_inputs] = len;
    c->num_inputs++;
    return 0;
}

int pow_server_add_target(PoWChallenge *c, const uint8_t *prefix, size_t prefix_len, uint32_t difficulty) {
    if (!c || c->num_targets >= POW_MAX_TARGETS) return -1;
    if (prefix_len > POW_MAX_PREFIX_LEN) return -1;
    
    memcpy(c->targets[c->num_targets].prefix, prefix, prefix_len);
    c->targets[c->num_targets].prefix_len = (uint8_t)prefix_len;
    c->targets[c->num_targets].difficulty = difficulty;
    c->num_targets++;
    return 0;
}

int pow_server_add_range(PoWChallenge *c, uint8_t min_char, uint8_t max_char) {
    if (!c || c->num_ranges >= POW_MAX_RANGES) return -1;
    c->ranges[c->num_ranges].min_char = min_char;
    c->ranges[c->num_ranges].max_char = max_char;
    c->num_ranges++;
    return 0;
}

void pow_server_set_limits(PoWChallenge *c, uint64_t max_tries, uint32_t max_time_ms, uint32_t max_mem_kb) {
    if (!c) return;
    c->max_tries = max_tries;
    c->max_time_ms = max_time_ms;
    c->max_memory_kb = max_mem_kb;
}

int pow_server_set_hash_params(PoWChallenge *c, uint32_t hash_out_len, uint32_t argon2_t_cost, uint32_t argon2_m_cost_kb, uint32_t argon2_parallelism, uint32_t argon2_encoded_len) {
    if (!c) return -1;
    c->hash_out_len = hash_out_len;
    c->argon2_t_cost = argon2_t_cost;
    c->argon2_m_cost_kb = argon2_m_cost_kb;
    c->argon2_parallelism = argon2_parallelism;
    c->argon2_encoded_len = argon2_encoded_len;
    return 0;
}
