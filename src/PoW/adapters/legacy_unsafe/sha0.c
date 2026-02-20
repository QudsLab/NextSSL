#include "../../core/pow_types.h"
#include <string.h>

#include "../../../legacy/unsafe/sha0/sha0.h"

extern uint64_t dhcm_sha0_wu(size_t input_size);

static int adapter_sha0_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    sha0_hash(input, input_len, output);
    return 0;
}

static int sha0_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    size_t typical_input_len = 264;
    *out_wu = dhcm_sha0_wu(typical_input_len);
    return 0;
}

static int sha0_get_mu(uint64_t* out_mu) {
    *out_mu = 0;
    return 0;
}

static POWAlgoAdapter sha0_adapter = {
    .hash = adapter_sha0_hash,
    .get_wu = sha0_get_wu,
    .get_mu = sha0_get_mu
};

POWAlgoAdapter* pow_adapter_sha0(void) {
    return &sha0_adapter;
}
