#include "../../core/pow_types.h"
#include "../../../primitives/hash/sponge_xof/shake/shake.h"
extern uint64_t dhcm_shake128_wu(size_t input_size);

static int pow_shake128_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    // Default output length for PoW: 32 bytes (256 bits)
    shake128_hash(input, input_len, output, 32);
    return 0;
}

static int shake128_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    size_t typical_input_len = 264;
    *out_wu = dhcm_shake128_wu(typical_input_len);
    return 0;
}

static int shake128_get_mu(uint64_t* out_mu) {
    *out_mu = 0;
    return 0;
}

static POWAlgoAdapter shake128_adapter = {
    .hash = pow_shake128_hash,
    .get_wu = shake128_get_wu,
    .get_mu = shake128_get_mu
};

POWAlgoAdapter* pow_adapter_shake128(void) {
    return &shake128_adapter;
}
