#include "../../core/pow_types.h"
#include <string.h>

#include "../../../legacy/unsafe/md2/md2.h"

extern uint64_t dhcm_md2_wu(size_t input_size);

static int adapter_md2_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    md2_hash(input, input_len, output);
    return 0;
}

static int md2_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    size_t typical_input_len = 264;
    *out_wu = dhcm_md2_wu(typical_input_len);
    return 0;
}

static int md2_get_mu(uint64_t* out_mu) {
    *out_mu = 0;
    return 0;
}

static POWAlgoAdapter md2_adapter = {
    .hash = adapter_md2_hash,
    .get_wu = md2_get_wu,
    .get_mu = md2_get_mu
};

POWAlgoAdapter* pow_adapter_md2(void) {
    return &md2_adapter;
}
