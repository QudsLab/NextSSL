#include "../../core/pow_types.h"
#include <string.h>

extern int leyline_shake128(const uint8_t* input, size_t len, uint8_t* output, size_t out_len);
extern uint64_t dhcm_shake128_wu(size_t input_size);

static int shake128_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    // Default output length for PoW: 32 bytes (256 bits)
    return leyline_shake128(input, input_len, output, 32);
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
    .hash = shake128_hash,
    .get_wu = shake128_get_wu,
    .get_mu = shake128_get_mu
};

POWAlgoAdapter* pow_adapter_shake128(void) {
    return &shake128_adapter;
}
