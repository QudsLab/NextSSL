#include "../../core/pow_types.h"
#include <string.h>

#include "../../../legacy/alive/sha1/sha1.h"

extern uint64_t dhcm_sha1_wu(size_t input_size);

static int adapter_sha1_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    sha1_hash(input, input_len, output);
    return 0;
}

static int sha1_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    size_t typical_input_len = 264;
    *out_wu = dhcm_sha1_wu(typical_input_len);
    return 0;
}

static int sha1_get_mu(uint64_t* out_mu) {
    *out_mu = 0;
    return 0;
}

static POWAlgoAdapter sha1_adapter = {
    .hash = adapter_sha1_hash,
    .get_wu = sha1_get_wu,
    .get_mu = sha1_get_mu
};

POWAlgoAdapter* pow_adapter_sha1(void) {
    return &sha1_adapter;
}
