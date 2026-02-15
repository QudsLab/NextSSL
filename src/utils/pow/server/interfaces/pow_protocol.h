#ifndef LEYLINE_POW_PROTOCOL_H
#define LEYLINE_POW_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// --- Constants & Limits ---
#define POW_MAX_INPUTS 8
#define POW_MAX_TARGETS 4
#define POW_MAX_NONCE_LEN 64
#define POW_MAX_PREFIX_LEN 32
#define POW_MAX_RANGES 8

// --- Algorithms ---
typedef enum {
    POW_ALGO_INVALID = 0,
    POW_ALGO_BLAKE3 = 1,
    POW_ALGO_SHA256 = 2,
    POW_ALGO_SHA3_256 = 3,
    POW_ALGO_ARGON2ID = 4,
    
    // Legacy (Optional, Disabled by Default in Safety Layer)
    POW_ALGO_MD5 = 0x80,
    POW_ALGO_SHA1 = 0x81
} PoWAlgorithm;

// --- Target Definition ---
// A target defines success criteria.
// If multiple targets are present, satisfying ANY one is sufficient (OR logic).
typedef struct {
    // Prefix Matching (Convenience)
    uint8_t prefix[POW_MAX_PREFIX_LEN];
    uint8_t prefix_len;
    uint32_t difficulty; // Repetition count of the prefix
    
    // Numeric Difficulty (Internal / Advanced)
    // If set > 0, hash interpreted as integer must be < target_threshold
    // This allows for granular difficulty control beyond byte alignment.
    uint64_t target_threshold_u64; // High 64-bits of target
} PoWTarget;

// --- Nonce Constraint ---
typedef struct {
    uint8_t min_char;
    uint8_t max_char;
} PoWCharRange;

// --- The Binary Challenge Struct ---
// This is the internal representation of a challenge.
typedef struct {
    uint32_t version;
    PoWAlgorithm algo;
    
    // Inputs (Batch)
    // Data is allocated during deserialization
    uint8_t *inputs[POW_MAX_INPUTS];
    size_t input_lens[POW_MAX_INPUTS];
    uint32_t num_inputs;

    // Targets (OR Logic)
    PoWTarget targets[POW_MAX_TARGETS];
    uint32_t num_targets;

    // Constraints
    PoWCharRange ranges[POW_MAX_RANGES];
    uint32_t num_ranges;
    
    // Limits & Safety
    uint64_t max_tries;
    uint32_t max_time_ms;
    uint32_t max_memory_kb; // Explicit memory limit for memory-hard algos
    uint32_t hash_out_len;
    uint32_t argon2_t_cost;
    uint32_t argon2_m_cost_kb;
    uint32_t argon2_parallelism;
    uint32_t argon2_encoded_len;
    
} PoWChallenge;

// --- Error Codes ---
typedef enum {
    POW_OK = 0,
    POW_ERR_INVALID_FORMAT,
    POW_ERR_UNKNOWN_ALGO,
    POW_ERR_SAFETY_VIOLATION, // Resource limit exceeded
    POW_ERR_TIMEOUT,
    POW_ERR_NOT_FOUND,
    POW_ERR_INTERNAL,
    POW_ERR_MEMORY
} PoWError;

// --- Helper Functions ---
void pow_challenge_free(PoWChallenge *challenge);

// Encode a challenge structure into a Base64 string
// Returns 0 on success
int pow_challenge_encode(const PoWChallenge *c, char *out_b64, size_t max_len);

// Decode a Base64 string into a challenge structure
// Returns 0 on success
int pow_challenge_decode(const char *b64_str, PoWChallenge *out_c);

#ifdef __cplusplus
}
#endif

#endif // LEYLINE_POW_PROTOCOL_H
