#include "../../core/pow_types.h"
#include "../../../primitives/hash/fast/blake3/blake3.h"
extern uint64_t dhcm_blake3_wu(size_t input_size);

static int blake3_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    (void)params;
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, input_len);
    blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);
    return 0;
}

static int blake3_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    size_t typical_input_len = 264;
    *out_wu = dhcm_blake3_wu(typical_input_len);
    return 0;
}

static int blake3_get_mu(uint64_t* out_mu) {
    *out_mu = 0; // BLAKE3 is not memory hard
    return 0;
}

static POWAlgoAdapter blake3_adapter = {
    .hash = blake3_hash,
    .get_wu = blake3_get_wu,
    .get_mu = blake3_get_mu
};

POWAlgoAdapter* pow_adapter_blake3(void) {
    return &blake3_adapter;
}
