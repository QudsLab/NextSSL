#ifndef nextssl_POW_SERVER_H
#define nextssl_POW_SERVER_H

#include "pow_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

// Initialize a new challenge structure
int pow_server_init_challenge(PoWChallenge *c, PoWAlgorithm algo);

// Add input data to challenge
int pow_server_add_input(PoWChallenge *c, const uint8_t *data, size_t len);

// Add target (Prefix + Difficulty)
int pow_server_add_target(PoWChallenge *c, const uint8_t *prefix, size_t prefix_len, uint32_t difficulty);

// Tune difficulty to match a target time (in milliseconds)
// Uses the complexity calculator to estimate required operations.
int pow_server_tune_difficulty(PoWChallenge *c, uint32_t target_time_ms);

// Add range constraint
int pow_server_add_range(PoWChallenge *c, uint8_t min_char, uint8_t max_char);

// Set limits
void pow_server_set_limits(PoWChallenge *c, uint64_t max_tries, uint32_t max_time_ms, uint32_t max_mem_kb);
int pow_server_set_hash_params(PoWChallenge *c, uint32_t hash_out_len, uint32_t argon2_t_cost, uint32_t argon2_m_cost_kb, uint32_t argon2_parallelism, uint32_t argon2_encoded_len);

// Verify a solution for a specific input index
// Returns 1 if valid, 0 if invalid
int pow_server_verify(const PoWChallenge *c, const uint8_t *nonce, size_t nonce_len, uint32_t input_index);

#ifdef __cplusplus
}
#endif

#endif // nextssl_POW_SERVER_H
