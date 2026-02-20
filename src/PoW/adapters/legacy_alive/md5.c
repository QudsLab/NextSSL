#include "../../core/pow_types.h"
#include <string.h>

#include "../../../legacy/alive/md5/md5.h"

extern uint64_t dhcm_md5_wu(size_t input_size);

static int adapter_md5_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    md5_hash(input, input_len, output);
    return 0;
}

static int md5_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    size_t typical_input_len = 264;
    *out_wu = dhcm_md5_wu(typical_input_len);
    return 0;
}

static int md5_get_mu(uint64_t* out_mu) {
    *out_mu = 0;
    return 0;
}

static POWAlgoAdapter md5_adapter = {
    .hash = adapter_md5_hash,
    .get_wu = md5_get_wu,
    .get_mu = md5_get_mu
};

POWAlgoAdapter* pow_adapter_md5(void) {
    return &md5_adapter;
}
