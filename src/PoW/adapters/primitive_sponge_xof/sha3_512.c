#include "../../core/pow_types.h"
#include "../../../primitives/hash/sponge_xof/sha3/sha3.h"
extern uint64_t dhcm_sha3_512_wu(size_t input_size);

static int pow_sha3_512_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    sha3_512_hash(input, input_len, output);
    return 0;
}

static int sha3_512_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    size_t typical_input_len = 264;
    *out_wu = dhcm_sha3_512_wu(typical_input_len);
    return 0;
}

static int sha3_512_get_mu(uint64_t* out_mu) {
    *out_mu = 0;
    return 0;
}

static POWAlgoAdapter sha3_512_adapter = {
    .hash = pow_sha3_512_hash,
    .get_wu = sha3_512_get_wu,
    .get_mu = sha3_512_get_mu
};

POWAlgoAdapter* pow_adapter_sha3_512(void) {
    return &sha3_512_adapter;
}
