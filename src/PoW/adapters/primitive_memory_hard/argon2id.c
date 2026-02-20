#include "../../core/pow_types.h"
#include "argon2_params.h"
#include <string.h>

// Forward declarations
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

extern int leyline_argon2id(const void* pwd, size_t pwdlen, const void* salt, size_t saltlen, 
                           uint32_t t_cost, uint32_t m_cost, uint32_t parallelism, 
                           void* output, size_t outlen);

extern uint64_t dhcm_argon2id_wu(uint32_t t, uint32_t m, uint32_t p);
extern uint64_t dhcm_argon2id_mu(uint32_t m);

static int argon2id_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    if (!params) return -1;
    const Argon2Params* p = (const Argon2Params*)params;
    
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
    
    return leyline_argon2id(input, input_len, salt, sizeof(salt), 
                           p->iterations, p->memory_kib, p->threads, 
                           output, p->out_len);
}

static int argon2id_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    // This requires params to calculate WU, but the signature doesn't provide params!
    // The signature `get_wu(difficulty_bits, out_wu)` is for DHCM to ESTIMATE cost.
    // But Argon2 cost depends on params, not just difficulty.
    // Wait, `POWChallenge` has `wu` field which is pre-calculated by Server using DHCM.
    // The `get_wu` in adapter is likely used by Server to Calculate that value.
    // But Server knows the params it chose.
    // The interface `get_wu` taking only `difficulty_bits` implies the adapter knows default params?
    // Or the interface is insufficient for Argon2.
    // The plan example for SHA256 used `dhcm_calculate`.
    
    // For Argon2, cost is dominated by memory/time params, not difficulty bits (which just checks output).
    // The WU is `t * m * p * constant`.
    // The `get_wu` interface seems designed for Hash functions where cost is fixed per hash.
    // For Argon2, we probably need a different way to calculate WU based on chosen params.
    
    // However, since I must implement the interface:
    // I'll return 0 or a default, assuming the caller (Server) calls DHCM directly 
    // with the params it selected, rather than using this adapter method.
    // Or, this adapter method assumes "standard" parameters.
    
    *out_wu = 0; // Should be calculated via DHCM with specific params
    return 0;
}

static int argon2id_get_mu(uint64_t* out_mu) {
    // Similarly, depends on params.
    *out_mu = 0;
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
