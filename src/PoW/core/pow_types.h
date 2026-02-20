#ifndef POW_TYPES_H
#define POW_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// ══════════════════════════════════════════════════════════════════
// Core Data Structures
// ══════════════════════════════════════════════════════════════════

typedef struct {
    uint8_t  version;                   // Protocol version (1 = POWv1)
    uint8_t  challenge_id[16];          // Unique challenge identifier (UUID)
    
    char     algorithm_id[32];          // Algorithm name (e.g., "argon2id", "sha256")
    uint8_t  context[256];              // Server-controlled context data
    size_t   context_len;               // Actual context length
    
    uint8_t  target[64];                // Binary difficulty target (H < target)
    size_t   target_len;                // Target length (usually 32 bytes)
    uint32_t difficulty_bits;           // Leading zero bits required
    
    uint64_t wu;                        // Expected Work Units (from DHCM)
    uint64_t mu;                        // Expected Memory Units (from DHCM)
    
    uint64_t expires_unix;              // Expiry timestamp (Unix seconds)
    
    // Algorithm-specific parameters (opaque to core)
    void*    algo_params;               // Pointer to AlgoParams struct
    size_t   algo_params_size;
} POWChallenge;

typedef struct {
    uint8_t  challenge_id[16];          // Must match challenge
    uint64_t nonce;                     // Solved nonce value
    uint8_t  hash_output[64];           // Resulting hash (H(context || nonce))
    size_t   hash_output_len;           // Hash length
    
    // Client metadata (always included)
    double   solve_time_seconds;        // Total time taken to solve
    uint64_t attempts;                  // Number of nonces tried
} POWSolution;

typedef struct {
    uint32_t default_difficulty_bits;   // Default difficulty (e.g., 20)
    uint64_t max_wu_per_challenge;      // WU limit (prevent DoS)
    uint64_t challenge_ttl_seconds;     // Time-to-live (e.g., 600 = 10 min)
    
    // Whitelist of allowed algorithms
    char*    allowed_algos[32];
    size_t   allowed_algos_count;
    
    // Rate limiting
    uint32_t max_challenges_per_ip;     // Per time window
    uint32_t rate_limit_window_seconds;
} POWConfig;

// Algorithm Adapter Interface
typedef struct {
    // Hash function now takes optional parameters (for Argon2, etc.)
    int (*hash)(const uint8_t* input, size_t input_len, const void* params, uint8_t* output);
    int (*get_wu)(uint32_t difficulty_bits, uint64_t* out_wu);
    int (*get_mu)(uint64_t* out_mu);
    
    // Get default parameters for challenge generation (optional, can be NULL)
    int (*get_default_params)(void** out_params, size_t* out_len);
} POWAlgoAdapter;

#endif // POW_TYPES_H
