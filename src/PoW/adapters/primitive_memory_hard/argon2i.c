#include "../../core/pow_types.h"
#include "argon2_params.h"
#include <string.h>

extern int leyline_argon2i(const void* pwd, size_t pwdlen, const void* salt, size_t saltlen, 
                           uint32_t t_cost, uint32_t m_cost, uint32_t parallelism, 
                           void* output, size_t outlen);

static int argon2i_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    if (!params) return -1;
    const Argon2Params* p = (const Argon2Params*)params;
    
    uint8_t salt[16] = {0}; 
    
    return leyline_argon2i(input, input_len, salt, sizeof(salt), 
                           p->iterations, p->memory_kib, p->threads, 
                           output, p->out_len);
}

static int argon2i_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    *out_wu = 0; 
    return 0;
}

static int argon2i_get_mu(uint64_t* out_mu) {
    *out_mu = 0;
    return 0;
}

static int argon2i_get_default_params(void** out_params, size_t* out_len) {
    static Argon2Params default_params = {
        .out_len = 32,
        .memory_kib = 16,
        .iterations = 1,
        .threads = 1
    };
    *out_params = (void*)&default_params;
    *out_len = sizeof(Argon2Params);
    return 0;
}

static POWAlgoAdapter argon2i_adapter = {
    .hash = argon2i_hash,
    .get_wu = argon2i_get_wu,
    .get_mu = argon2i_get_mu,
    .get_default_params = argon2i_get_default_params
};

POWAlgoAdapter* pow_adapter_argon2i(void) {
    return &argon2i_adapter;
}
