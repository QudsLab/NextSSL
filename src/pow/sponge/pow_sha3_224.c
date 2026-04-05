/* pow_sha3_224.c — PoW adapter: sha3-224 */
#include "../core/pow_types.h"
#include "../dhcm/dhcm_core.h"
#include "../../hash/interface/hash_registry.h"
#include <stdint.h>
#include <stddef.h>

#define HASH_OPS_CTX_MAX 2048

static int sha3_224_hash(const uint8_t *in, size_t len,
                          const void *params, uint8_t *out) {
    (void)params;
    const hash_ops_t *h = hash_lookup("sha3-224");
    if (!h) return -1;
    uint8_t ctx[HASH_OPS_CTX_MAX];
    h->init(ctx);
    h->update(ctx, in, len);
    h->final(ctx, out);
    return 0;
}

static int sha3_224_get_cost(uint32_t difficulty_bits, DHCMResult *r) {
    DHCMParams p = {0};
    p.algorithm            = DHCM_SHA3_224;
    p.difficulty_model     = DHCM_DIFFICULTY_TARGET_BASED;
    p.target_leading_zeros = difficulty_bits;
    p.input_size           = 64;
    return dhcm_core_calculate(&p, r);
}

static const pow_adapter_t sha3_224_adapter = {
    .name     = "sha3-224",
    .hash     = sha3_224_hash,
    .get_cost = sha3_224_get_cost,
};

const pow_adapter_t *pow_adapter_sha3_224(void) { return &sha3_224_adapter; }
