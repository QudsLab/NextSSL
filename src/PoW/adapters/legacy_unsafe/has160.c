#include "../../core/pow_types.h"
#include <string.h>

#include "../../../legacy/unsafe/has160/has160.h"

extern uint64_t dhcm_has160_wu(size_t input_size);

static int adapter_has160_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    has160_hash(input, input_len, output);
    return 0;
}

static int has160_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    size_t typical_input_len = 264;
    *out_wu = dhcm_has160_wu(typical_input_len);
    return 0;
}

static int has160_get_mu(uint64_t* out_mu) {
    *out_mu = 0;
    return 0;
}

static POWAlgoAdapter has160_adapter = {
    .hash = adapter_has160_hash,
    .get_wu = has160_get_wu,
    .get_mu = has160_get_mu
};

POWAlgoAdapter* pow_adapter_has160(void) {
    return &has160_adapter;
}
