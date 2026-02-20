#include "../../core/pow_types.h"
#include <string.h>

extern int leyline_shake256(const uint8_t* input, size_t len, uint8_t* output, size_t out_len);
extern uint64_t dhcm_shake256_wu(size_t input_size);

static int shake256_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    // Default output length for PoW: 64 bytes (512 bits)
    return leyline_shake256(input, input_len, output, 64);
}

static int shake256_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    size_t typical_input_len = 264;
    *out_wu = dhcm_shake256_wu(typical_input_len);
    return 0;
}

static int shake256_get_mu(uint64_t* out_mu) {
    *out_mu = 0;
    return 0;
}

static POWAlgoAdapter shake256_adapter = {
    .hash = shake256_hash,
    .get_wu = shake256_get_wu,
    .get_mu = shake256_get_mu
};

POWAlgoAdapter* pow_adapter_shake256(void) {
    return &shake256_adapter;
}
