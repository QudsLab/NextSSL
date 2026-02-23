#include "../../core/pow_types.h"
#include "../../../primitives/hash/fast/sha256/sha256.h"
extern uint64_t dhcm_sha256_wu(size_t input_size);

static int sha256_hash(const uint8_t* input, size_t input_len, const void* params, uint8_t* output) {
    // SHA-256 doesn't use params
    (void)params;
    sha256(input, input_len, output);
    return 0;
}

static int sha256_get_wu(uint32_t difficulty_bits, uint64_t* out_wu) {
    // Basic WU calculation for SHA-256 PoW
    // PoW typically hashes context + nonce.
    // Assuming input size ~ 256 bytes context + 8 bytes nonce = 264 bytes
    // This is approximate.
    size_t typical_input_len = 264;
    *out_wu = dhcm_sha256_wu(typical_input_len);
    return 0;
}

static int sha256_get_mu(uint64_t* out_mu) {
    // SHA-256 has negligible memory usage (constant state size)
    *out_mu = 0;
    return 0;
}

static POWAlgoAdapter sha256_adapter = {
    .hash = sha256_hash,
    .get_wu = sha256_get_wu,
    .get_mu = sha256_get_mu
};

POWAlgoAdapter* pow_adapter_sha256(void) {
    return &sha256_adapter;
}
