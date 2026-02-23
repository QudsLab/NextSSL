#include "../../core/pow_types.h"
#include "argon2_params.h"
#include "../../../utils/hash/primitive_memory_hard.h"
#include <string.h>

static int argon2i_get_default_params(void** out_params, size_t* out_len);

extern int leyline_argon2i(const uint8_t *pwd, size_t pwd_len, 
                           const uint8_t *salt, size_t salt_len,
                           const LeylineArgon2Params *params,
                           uint8_t *out, size_t out_len);

extern uint64_t dhcm_argon2i_wu(uint32_t t, uint32_t m, uint32_t p);
extern uint64_t dhcm_argon2i_mu(uint32_t m);

static int argon2i_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    const Argon2Params* p = (const Argon2Params*)params;
    if (!p) {
        size_t len = 0;
        argon2i_get_default_params((void**)&p, &len);
        if (!p) return -1;
    }
    
    uint8_t salt[16] = {0}; 
    
    LeylineArgon2Params lp = {
        .t_cost = p->iterations,
        .m_cost_kb = p->memory_kib,
        .parallelism = p->threads
    };
    return leyline_argon2i(input, input_len, salt, sizeof(salt), &lp, output, p->out_len);
}

static int argon2i_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    (void)difficulty_bits;
    Argon2Params* params;
    size_t len;
    argon2i_get_default_params((void**)&params, &len);
    
    if (params) {
        *out_wu = dhcm_argon2i_wu(params->iterations, params->memory_kib, params->threads);
    } else {
        *out_wu = 0;
    }
    return 0;
}

static int argon2i_get_mu(uint64_t* out_mu) {
    Argon2Params* params;
    size_t len;
    argon2i_get_default_params((void**)&params, &len);
    
    if (params) {
        *out_mu = dhcm_argon2i_mu(params->memory_kib);
    } else {
        *out_mu = 0;
    }
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
