#include "../../core/pow_types.h"
#include <string.h>

extern int leyline_keccak_256(const uint8_t* input, size_t len, uint8_t* output);
extern uint64_t dhcm_keccak_256_wu(size_t input_size);

static int keccak_256_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    return leyline_keccak_256(input, input_len, output);
}

static int keccak_256_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    size_t typical_input_len = 264;
    *out_wu = dhcm_keccak_256_wu(typical_input_len);
    return 0;
}

static int keccak_256_get_mu(uint64_t* out_mu) {
    *out_mu = 0;
    return 0;
}

static POWAlgoAdapter keccak_256_adapter = {
    .hash = keccak_256_hash,
    .get_wu = keccak_256_get_wu,
    .get_mu = keccak_256_get_mu
};

POWAlgoAdapter* pow_adapter_keccak_256(void) {
    return &keccak_256_adapter;
}
