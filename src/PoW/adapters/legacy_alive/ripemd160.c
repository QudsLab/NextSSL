#include "../../core/pow_types.h"
#include <string.h>

#include "../../../legacy/alive/ripemd160/ripemd160.h"

extern uint64_t dhcm_ripemd160_wu(size_t input_size);

static int adapter_ripemd160_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    ripemd160_hash(input, input_len, output);
    return 0;
}

static int ripemd160_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    size_t typical_input_len = 264;
    *out_wu = dhcm_ripemd160_wu(typical_input_len);
    return 0;
}

static int ripemd160_get_mu(uint64_t* out_mu) {
    *out_mu = 0;
    return 0;
}

static POWAlgoAdapter ripemd160_adapter = {
    .hash = adapter_ripemd160_hash,
    .get_wu = ripemd160_get_wu,
    .get_mu = ripemd160_get_mu
};

POWAlgoAdapter* pow_adapter_ripemd160(void) {
    return &ripemd160_adapter;
}
