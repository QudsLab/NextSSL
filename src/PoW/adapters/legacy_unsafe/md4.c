#include "../../core/pow_types.h"
#include <string.h>

#include "../../../legacy/unsafe/md4/md4.h"

extern uint64_t dhcm_md4_wu(size_t input_size);

static int adapter_md4_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    md4_hash(input, input_len, output);
    return 0;
}

static int md4_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    size_t typical_input_len = 264;
    *out_wu = dhcm_md4_wu(typical_input_len);
    return 0;
}

static int md4_get_mu(uint64_t* out_mu) {
    *out_mu = 0;
    return 0;
}

static POWAlgoAdapter md4_adapter = {
    .hash = adapter_md4_hash,
    .get_wu = md4_get_wu,
    .get_mu = md4_get_mu
};

POWAlgoAdapter* pow_adapter_md4(void) {
    return &md4_adapter;
}
