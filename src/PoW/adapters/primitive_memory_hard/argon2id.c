#include "../../core/pow_types.h"
#include "argon2_params.h"
#include "../../../utils/hash/primitive_memory_hard.h"
#include <string.h>

// Forward declarations
static int argon2id_get_default_params(void** out_params, size_t* out_len);

// Assuming leyline_argon2id signature:
// int leyline_argon2id(const void* pwd, size_t pwd_len, const void* salt, size_t salt_len, 
//                      uint32_t t, uint32_t m, uint32_t p, void* out, size_t out_len);
// But PoW context usually puts everything in "input" (context || nonce).
// For Argon2, we treat "input" as the message (password) and use a fixed salt or empty salt?
// Or we split input?
// In standard PoW (e.g. various crypto coins), Argon2 usually takes the header as input and salt.
// Let's assume we use the input as BOTH password and salt, or just password with empty salt.
// However, Argon2 requires a salt.
// Let's use the input as password, and a fixed salt or part of input as salt.
// Ideally, `context` is the salt and `nonce` is the password?
// But `input` is `context || nonce`.
// Let's assume we use the `input` as the Password, and a fixed Salt (or derived from input).
// OR better: The adapter implementation decides.
// For this implementation, I will use `input` as Password and a zero-salt or specific salt.

extern int leyline_argon2id(const uint8_t *pwd, size_t pwd_len, 
                            const uint8_t *salt, size_t salt_len,
                            const LeylineArgon2Params *params,
                            uint8_t *out, size_t out_len);

extern uint64_t dhcm_argon2id_wu(uint32_t t, uint32_t m, uint32_t p);
extern uint64_t dhcm_argon2id_mu(uint32_t m);

static int argon2id_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    const Argon2Params* p = (const Argon2Params*)params;
    if (!p) {
        size_t len = 0;
        argon2id_get_default_params((void**)&p, &len);
        if (!p) return -1;
    }
    
    // Use input as password. Use a fixed salt for now (or part of input).
    // Using a fixed salt is secure enough for PoW if the input (nonce) is unique.
    // Actually, context should be unique per challenge.
    // Let's use the first 16 bytes of input as salt if available, or a fixed salt.
    // Better: use input as Password, and input as Salt (or a subset).
    // Let's use a 16-byte fixed salt to satisfy the API.
    uint8_t salt[16] = {0}; 
    // In a real system, the salt should be the Challenge ID or Context.
    // But here we only have the concatenated input.
    // Let's use the input as salt too? No, salt should be distinct.
    
    LeylineArgon2Params lp = {
        .t_cost = p->iterations,
        .m_cost_kb = p->memory_kib,
        .parallelism = p->threads
    };
    return leyline_argon2id(input, input_len, salt, sizeof(salt), &lp, output, p->out_len);
}

static int argon2id_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    (void)difficulty_bits; // Not used for memory-hard cost model
    
    // Use default params to estimate cost
    Argon2Params* params;
    size_t len;
    argon2id_get_default_params((void**)&params, &len);
    
    if (params) {
        *out_wu = dhcm_argon2id_wu(params->iterations, params->memory_kib, params->threads);
    } else {
        *out_wu = 0;
    }
    return 0;
}

static int argon2id_get_mu(uint64_t* out_mu) {
    // Use default params to estimate memory usage
    Argon2Params* params;
    size_t len;
    argon2id_get_default_params((void**)&params, &len);
    
    if (params) {
        *out_mu = dhcm_argon2id_mu(params->memory_kib);
    } else {
        *out_mu = 0;
    }
    return 0;
}

static int argon2id_get_default_params(void** out_params, size_t* out_len) {
    // Return static default params for Argon2
    static Argon2Params default_params = {
        .out_len = 32,
        .memory_kib = 16, // Default 16KB
        .iterations = 1,
        .threads = 1
    };
    *out_params = (void*)&default_params;
    *out_len = sizeof(Argon2Params);
    return 0;
}

static POWAlgoAdapter argon2id_adapter = {
    .hash = argon2id_hash,
    .get_wu = argon2id_get_wu,
    .get_mu = argon2id_get_mu,
    .get_default_params = argon2id_get_default_params
};

POWAlgoAdapter* pow_adapter_argon2id(void) {
    return &argon2id_adapter;
}
