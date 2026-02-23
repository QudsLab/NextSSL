#include "../../core/pow_types.h"
#include "../../../primitives/hash/fast/blake2s/blake2s.h"

extern uint64_t dhcm_blake2s_wu(size_t input_size);

static int pow_blake2s_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    blake2s_256_hash(input, input_len, output);
    return 0;
}

static int blake2s_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    size_t typical_input_len = 264;
    *out_wu = dhcm_blake2s_wu(typical_input_len);
    return 0;
}

static int blake2s_get_mu(uint64_t* out_mu) {
    *out_mu = 0;
    return 0;
}

static POWAlgoAdapter blake2s_adapter = {
    .hash = pow_blake2s_hash,
    .get_wu = blake2s_get_wu,
    .get_mu = blake2s_get_mu
};

POWAlgoAdapter* pow_adapter_blake2s(void) {
    return &blake2s_adapter;
}
