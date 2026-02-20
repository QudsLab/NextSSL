#include "../../core/pow_types.h"
#include <string.h>

#include "../../../legacy/alive/whirlpool/whirlpool.h"

extern uint64_t dhcm_whirlpool_wu(size_t input_size);

static int adapter_whirlpool_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    whirlpool_hash(input, input_len, output);
    return 0;
}

static int whirlpool_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    size_t typical_input_len = 264;
    *out_wu = dhcm_whirlpool_wu(typical_input_len);
    return 0;
}

static int whirlpool_get_mu(uint64_t* out_mu) {
    *out_mu = 0;
    return 0;
}

static POWAlgoAdapter whirlpool_adapter = {
    .hash = adapter_whirlpool_hash,
    .get_wu = whirlpool_get_wu,
    .get_mu = whirlpool_get_mu
};

POWAlgoAdapter* pow_adapter_whirlpool(void) {
    return &whirlpool_adapter;
}
