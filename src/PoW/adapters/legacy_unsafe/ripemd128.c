#include "../../core/pow_types.h"
#include <string.h>

#include "../../../legacy/unsafe/ripemd128/ripemd128.h"

extern uint64_t dhcm_ripemd128_wu(size_t input_size);

static int adapter_ripemd128_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    ripemd128_hash(input, input_len, output);
    return 0;
}

static int ripemd128_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    size_t typical_input_len = 264;
    *out_wu = dhcm_ripemd128_wu(typical_input_len);
    return 0;
}

static int ripemd128_get_mu(uint64_t* out_mu) {
    *out_mu = 0;
    return 0;
}

static POWAlgoAdapter ripemd128_adapter = {
    .hash = adapter_ripemd128_hash,
    .get_wu = ripemd128_get_wu,
    .get_mu = ripemd128_get_mu
};

POWAlgoAdapter* pow_adapter_ripemd128(void) {
    return &ripemd128_adapter;
}
