#include "../../core/pow_types.h"
#include <string.h>

#include "../../../legacy/alive/nt_hash/nt.h"

extern uint64_t dhcm_nt_wu(size_t input_size);

static int adapter_nt_hash_func(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    nt_hash_unicode(input, input_len, output);
    return 0;
}

static int nt_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    size_t typical_input_len = 264;
    *out_wu = dhcm_nt_wu(typical_input_len);
    return 0;
}

static int nt_get_mu(uint64_t* out_mu) {
    *out_mu = 0;
    return 0;
}

static POWAlgoAdapter nt_adapter = {
    .hash = adapter_nt_hash_func,
    .get_wu = nt_get_wu,
    .get_mu = nt_get_mu
};

POWAlgoAdapter* pow_adapter_nt(void) {
    return &nt_adapter;
}
