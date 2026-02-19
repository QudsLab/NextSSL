#ifndef DHCM_TYPES_H
#define DHCM_TYPES_H

#include <stdint.h>
#include <stddef.h>

// ══════════════════════════════════════════════════════════════════
// Algorithm identifier
// ══════════════════════════════════════════════════════════════════
typedef enum {
    // Primitive Fast
    DHCM_SHA256 = 0x0100,
    DHCM_SHA512 = 0x0101,
    DHCM_BLAKE2B = 0x0102,
    DHCM_BLAKE2S = 0x0103,
    DHCM_BLAKE3 = 0x0104,
    
    // Primitive Memory-Hard
    DHCM_ARGON2ID = 0x0200,
    DHCM_ARGON2I = 0x0201,
    DHCM_ARGON2D = 0x0202,
    
    // Primitive Sponge/XOF
    DHCM_SHA3_256 = 0x0300,
    DHCM_SHA3_512 = 0x0301,
    DHCM_KECCAK_256 = 0x0302,
    DHCM_SHAKE128 = 0x0303,
    DHCM_SHAKE256 = 0x0304,
    
    // Legacy Alive
    DHCM_MD5 = 0x0400,
    DHCM_SHA1 = 0x0401,
    DHCM_RIPEMD160 = 0x0402,
    DHCM_WHIRLPOOL = 0x0403,
    DHCM_NT = 0x0404,
    
    // Legacy Unsafe
    DHCM_MD2 = 0x0500,
    DHCM_MD4 = 0x0501,
    DHCM_SHA0 = 0x0502,
    DHCM_HAS160 = 0x0503,
    DHCM_RIPEMD128 = 0x0504,
    DHCM_RIPEMD256 = 0x0505,
    DHCM_RIPEMD320 = 0x0506,
} DHCMAlgorithm;

// ══════════════════════════════════════════════════════════════════
// Difficulty model type
// ══════════════════════════════════════════════════════════════════
typedef enum {
    DHCM_DIFFICULTY_NONE = 0,        // No difficulty (single hash)
    DHCM_DIFFICULTY_TARGET_BASED,    // Target-based PoW (e.g., leading zeros)
    DHCM_DIFFICULTY_ITERATION_BASED, // Fixed iteration count (e.g., Argon2)
} DHCMDifficultyModel;

// ══════════════════════════════════════════════════════════════════
// Input parameters
// ══════════════════════════════════════════════════════════════════
typedef struct {
    DHCMAlgorithm algorithm;         // Algorithm identifier
    DHCMDifficultyModel difficulty_model;
    
    // For target-based PoW
    uint32_t target_leading_zeros;   // Number of leading zero bits in hash output
    
    // For iteration-based PoW (e.g., Argon2)
    uint32_t iterations;             // Time cost (t_cost for Argon2)
    uint32_t memory_kb;              // Memory cost in KiB (m_cost for Argon2)
    uint32_t parallelism;            // Number of threads (p for Argon2)
    
    // Generic parameters
    size_t input_size;               // Size of input data (bytes)
    size_t output_size;              // Size of output hash (bytes)
} DHCMParams;

// ══════════════════════════════════════════════════════════════════
// Output result
// ══════════════════════════════════════════════════════════════════
typedef struct {
    // Cost per single evaluation
    uint64_t work_units_per_eval;    // WU for one hash computation
    uint64_t memory_units_per_eval;  // MU for one hash computation (in KB)
    
    // Difficulty-based expected trials
    double expected_trials;          // E[N] = expected number of trials to solve
    
    // Total cost
    uint64_t total_work_units;       // WU_total = WU × E[N]
    uint64_t total_memory_units;     // MU_total = MU × parallelism (if applicable)
    
    // Verification cost
    uint64_t verification_work_units; // WU to verify solution
    
    // Metadata
    const char *algorithm_name;      // Human-readable name
    const char *cost_model_version;  // Version of cost model used
} DHCMResult;

#endif // DHCM_TYPES_H
