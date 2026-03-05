#include "../../core/pow_types.h"
#include "../../../primitives/hash/sponge_xof/sha3_224/sha3_224.h"
/* SHA3-224 uses the same Keccak sponge rate as SHA3-256; reuse its WU metric. */
extern uint64_t dhcm_sha3_256_wu(size_t input_size);

static int pow_sha3_224_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    sha3_224_hash(input, input_len, output);
    return 0;
}

static int sha3_224_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    (void)difficulty_bits;
    size_t typical_input_len = 264;
    *out_wu = dhcm_sha3_256_wu(typical_input_len);
    return 0;
}

static int sha3_224_get_mu(uint64_t* out_mu) {
    *out_mu = 0;
    return 0;
}

static POWAlgoAdapter sha3_224_adapter = {
    .hash    = pow_sha3_224_hash,
    .get_wu  = sha3_224_get_wu,
    .get_mu  = sha3_224_get_mu
};

POWAlgoAdapter* pow_adapter_sha3_224(void) {
    return &sha3_224_adapter;
}
