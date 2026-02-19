#include "dhcm_core.h"
#include "dhcm_difficulty.h"
#include <string.h>

// Forward declarations of algorithm-specific cost functions
// Guarded by feature macros to allow partial builds

#ifdef DHCM_ENABLE_PRIMITIVE_FAST
extern uint64_t dhcm_sha256_wu(size_t input_size);
extern uint64_t dhcm_sha512_wu(size_t input_size);
extern uint64_t dhcm_blake2b_wu(size_t input_size);
extern uint64_t dhcm_blake2s_wu(size_t input_size);
extern uint64_t dhcm_blake3_wu(size_t input_size);
#endif

#ifdef DHCM_ENABLE_PRIMITIVE_MEMORY_HARD
extern uint64_t dhcm_argon2id_wu(uint32_t t, uint32_t m, uint32_t p);
extern uint64_t dhcm_argon2i_wu(uint32_t t, uint32_t m, uint32_t p);
extern uint64_t dhcm_argon2d_wu(uint32_t t, uint32_t m, uint32_t p);
extern uint64_t dhcm_argon2_mu(uint32_t m);
#endif

#ifdef DHCM_ENABLE_PRIMITIVE_SPONGE_XOF
extern uint64_t dhcm_sha3_256_wu(size_t input_size);
extern uint64_t dhcm_sha3_512_wu(size_t input_size);
extern uint64_t dhcm_keccak_256_wu(size_t input_size);
extern uint64_t dhcm_shake128_wu(size_t input_size, size_t output_size);
extern uint64_t dhcm_shake256_wu(size_t input_size, size_t output_size);
#endif

#ifdef DHCM_ENABLE_LEGACY_ALIVE
extern uint64_t dhcm_md5_wu(size_t input_size);
extern uint64_t dhcm_sha1_wu(size_t input_size);
extern uint64_t dhcm_ripemd160_wu(size_t input_size);
extern uint64_t dhcm_whirlpool_wu(size_t input_size);
extern uint64_t dhcm_nt_wu(size_t input_size);
#endif

#ifdef DHCM_ENABLE_LEGACY_UNSAFE
extern uint64_t dhcm_md2_wu(size_t input_size);
extern uint64_t dhcm_md4_wu(size_t input_size);
extern uint64_t dhcm_sha0_wu(size_t input_size);
extern uint64_t dhcm_has160_wu(size_t input_size);
extern uint64_t dhcm_ripemd128_wu(size_t input_size);
extern uint64_t dhcm_ripemd256_wu(size_t input_size);
extern uint64_t dhcm_ripemd320_wu(size_t input_size);
#endif

void dhcm_init_result(DHCMResult *result) {
    if (!result) return;
    memset(result, 0, sizeof(DHCMResult));
    result->expected_trials = 1.0;
    result->cost_model_version = "1.0.0";
}

int dhcm_core_calculate(const DHCMParams *params, DHCMResult *result) {
    if (!params || !result) return -1;
    
    dhcm_init_result(result);
    
    // 1. Calculate Per-Eval WU/MU based on algorithm
    switch (params->algorithm) {
        // --- Primitive Fast ---
        #ifdef DHCM_ENABLE_PRIMITIVE_FAST
        case DHCM_SHA256:
            result->work_units_per_eval = dhcm_sha256_wu(params->input_size);
            result->memory_units_per_eval = 1; // < 1KB
            result->algorithm_name = "SHA-256";
            break;
        case DHCM_SHA512:
            result->work_units_per_eval = dhcm_sha512_wu(params->input_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "SHA-512";
            break;
        case DHCM_BLAKE2B:
            result->work_units_per_eval = dhcm_blake2b_wu(params->input_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "BLAKE2b";
            break;
        case DHCM_BLAKE2S:
            result->work_units_per_eval = dhcm_blake2s_wu(params->input_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "BLAKE2s";
            break;
        case DHCM_BLAKE3:
            result->work_units_per_eval = dhcm_blake3_wu(params->input_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "BLAKE3";
            break;
        #endif
            
        // --- Primitive Memory Hard ---
        #ifdef DHCM_ENABLE_PRIMITIVE_MEMORY_HARD
        case DHCM_ARGON2ID:
            result->work_units_per_eval = dhcm_argon2id_wu(params->iterations, params->memory_kb, params->parallelism);
            result->memory_units_per_eval = dhcm_argon2_mu(params->memory_kb);
            result->algorithm_name = "Argon2id";
            break;
        case DHCM_ARGON2I:
            result->work_units_per_eval = dhcm_argon2i_wu(params->iterations, params->memory_kb, params->parallelism);
            result->memory_units_per_eval = dhcm_argon2_mu(params->memory_kb);
            result->algorithm_name = "Argon2i";
            break;
        case DHCM_ARGON2D:
            result->work_units_per_eval = dhcm_argon2d_wu(params->iterations, params->memory_kb, params->parallelism);
            result->memory_units_per_eval = dhcm_argon2_mu(params->memory_kb);
            result->algorithm_name = "Argon2d";
            break;
        #endif

        // --- Primitive Sponge/XOF ---
        #ifdef DHCM_ENABLE_PRIMITIVE_SPONGE_XOF
        case DHCM_SHA3_256:
            result->work_units_per_eval = dhcm_sha3_256_wu(params->input_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "SHA3-256";
            break;
        case DHCM_SHA3_512:
            result->work_units_per_eval = dhcm_sha3_512_wu(params->input_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "SHA3-512";
            break;
        case DHCM_KECCAK_256:
            result->work_units_per_eval = dhcm_keccak_256_wu(params->input_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "Keccak-256";
            break;
        case DHCM_SHAKE128:
            result->work_units_per_eval = dhcm_shake128_wu(params->input_size, params->output_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "SHAKE-128";
            break;
        case DHCM_SHAKE256:
            result->work_units_per_eval = dhcm_shake256_wu(params->input_size, params->output_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "SHAKE-256";
            break;
        #endif
            
        // --- Legacy Alive ---
        #ifdef DHCM_ENABLE_LEGACY_ALIVE
        case DHCM_MD5:
            result->work_units_per_eval = dhcm_md5_wu(params->input_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "MD5";
            break;
        case DHCM_SHA1:
            result->work_units_per_eval = dhcm_sha1_wu(params->input_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "SHA-1";
            break;
        case DHCM_RIPEMD160:
            result->work_units_per_eval = dhcm_ripemd160_wu(params->input_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "RIPEMD-160";
            break;
        case DHCM_WHIRLPOOL:
            result->work_units_per_eval = dhcm_whirlpool_wu(params->input_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "Whirlpool";
            break;
        case DHCM_NT:
            result->work_units_per_eval = dhcm_nt_wu(params->input_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "NT Hash";
            break;
        #endif
            
        // --- Legacy Unsafe ---
        #ifdef DHCM_ENABLE_LEGACY_UNSAFE
        case DHCM_MD2:
            result->work_units_per_eval = dhcm_md2_wu(params->input_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "MD2";
            break;
        case DHCM_MD4:
            result->work_units_per_eval = dhcm_md4_wu(params->input_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "MD4";
            break;
        case DHCM_SHA0:
            result->work_units_per_eval = dhcm_sha0_wu(params->input_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "SHA-0";
            break;
        case DHCM_HAS160:
            result->work_units_per_eval = dhcm_has160_wu(params->input_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "HAS-160";
            break;
        case DHCM_RIPEMD128:
            result->work_units_per_eval = dhcm_ripemd128_wu(params->input_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "RIPEMD-128";
            break;
        case DHCM_RIPEMD256:
            result->work_units_per_eval = dhcm_ripemd256_wu(params->input_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "RIPEMD-256";
            break;
        case DHCM_RIPEMD320:
            result->work_units_per_eval = dhcm_ripemd320_wu(params->input_size);
            result->memory_units_per_eval = 1;
            result->algorithm_name = "RIPEMD-320";
            break;
        #endif

        default:
            return -2; // Unknown algorithm
    }
    
    // 2. Calculate Expected Trials
    result->expected_trials = dhcm_calculate_expected_trials(params->difficulty_model, params->target_leading_zeros);
    
    // 3. Calculate Total Cost
    result->total_work_units = (uint64_t)(result->work_units_per_eval * result->expected_trials);
    result->total_memory_units = result->memory_units_per_eval * (params->parallelism > 0 ? params->parallelism : 1);
    
    // 4. Verification Cost
    result->verification_work_units = result->work_units_per_eval;
    
    #ifdef DHCM_ENABLE_PRIMITIVE_MEMORY_HARD
    if (params->algorithm == DHCM_ARGON2ID || params->algorithm == DHCM_ARGON2I || params->algorithm == DHCM_ARGON2D) {
        result->verification_work_units = result->work_units_per_eval;
    }
    #endif
    
    return 0;
}

const char* dhcm_get_algorithm_name(DHCMAlgorithm algo) {
    DHCMResult res;
    DHCMParams p = { .algorithm = algo };
    if (dhcm_core_calculate(&p, &res) == 0) {
        return res.algorithm_name;
    }
    return "Unknown";
}
