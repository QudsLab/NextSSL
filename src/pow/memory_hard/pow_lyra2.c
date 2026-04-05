/* pow_lyra2.c — PoW adapter: lyra2 */
#include "../core/pow_types.h"
#include "../dhcm/dhcm_core.h"
#include "../../hash/interface/hash_registry.h"
#include <stdint.h>
#include <stddef.h>

#define HASH_OPS_CTX_MAX 2048

static int lyra2_hash(const uint8_t *in, size_t len,
                       const void *params, uint8_t *out) {
    (void)params;
    const hash_ops_t *h = hash_lookup("lyra2");
    if (!h) return -1;
    uint8_t ctx[HASH_OPS_CTX_MAX];
    h->init(ctx);
    h->update(ctx, in, len);
    h->final(ctx, out);
    return 0;
}

static int lyra2_get_cost(uint32_t difficulty_bits, DHCMResult *r) {
    DHCMParams p = {0};
    p.algorithm            = DHCM_LYRA2;
    p.difficulty_model     = DHCM_DIFFICULTY_ITERATION_BASED;
    p.target_leading_zeros = difficulty_bits;
    return dhcm_core_calculate(&p, r);
}

static const pow_adapter_t lyra2_adapter = {
    .name     = "lyra2",
    .hash     = lyra2_hash,
    .get_cost = lyra2_get_cost,
};

const pow_adapter_t *pow_adapter_lyra2(void) { return &lyra2_adapter; }
