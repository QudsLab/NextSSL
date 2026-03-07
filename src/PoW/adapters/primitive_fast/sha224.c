#include "../../core/pow_types.h"
#include "../../../primitives/hash/fast/sha224/sha224.h"
/* SHA-224 has the same block structure as SHA-256; reuse its WU metric. */
extern uint64_t dhcm_sha256_wu(size_t input_size);

static int sha224_adapter_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    sha224_hash(input, input_len, output);
    return 0;
}

static int sha224_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    (void)difficulty_bits;
    size_t typical_input_len = 264;
    *out_wu = dhcm_sha256_wu(typical_input_len);
    return 0;
}

static int sha224_get_mu(uint64_t* out_mu) {
    *out_mu = 0;
    return 0;
}

static POWAlgoAdapter sha224_adapter = {
    .hash    = sha224_adapter_hash,
    .get_wu  = sha224_get_wu,
    .get_mu  = sha224_get_mu
};

POWAlgoAdapter* pow_adapter_sha224(void) {
    return &sha224_adapter;
}
