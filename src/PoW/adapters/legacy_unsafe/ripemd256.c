#include "../../core/pow_types.h"
#include <string.h>

#include "../../../legacy/unsafe/ripemd256/ripemd256.h"

extern uint64_t dhcm_ripemd256_wu(size_t input_size);

static int adapter_ripemd256_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    ripemd256_hash(input, input_len, output);
    return 0;
}

static int ripemd256_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    size_t typical_input_len = 264;
    *out_wu = dhcm_ripemd256_wu(typical_input_len);
    return 0;
}

static int ripemd256_get_mu(uint64_t* out_mu) {
    *out_mu = 0;
    return 0;
}

static POWAlgoAdapter ripemd256_adapter = {
    .hash = adapter_ripemd256_hash,
    .get_wu = ripemd256_get_wu,
    .get_mu = ripemd256_get_mu
};

POWAlgoAdapter* pow_adapter_ripemd256(void) {
    return &ripemd256_adapter;
}
