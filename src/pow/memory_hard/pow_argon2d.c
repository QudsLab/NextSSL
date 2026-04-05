/* pow_argon2d.c — PoW adapter: argon2d */
#include "../core/pow_types.h"
#include "../dhcm/dhcm_core.h"
#include "../../hash/interface/hash_registry.h"
#include <stdint.h>
#include <stddef.h>

#define HASH_OPS_CTX_MAX 2048

static int argon2d_hash(const uint8_t *in, size_t len,
                         const void *params, uint8_t *out) {
    (void)params;
    const hash_ops_t *h = hash_lookup("argon2d");
    if (!h) return -1;
    uint8_t ctx[HASH_OPS_CTX_MAX];
    h->init(ctx);
    h->update(ctx, in, len);
    h->final(ctx, out);
    return 0;
}

static int argon2d_get_cost(uint32_t difficulty_bits, DHCMResult *r) {
    DHCMParams p = {0};
    p.algorithm            = DHCM_ARGON2D;
    p.difficulty_model     = DHCM_DIFFICULTY_ITERATION_BASED;
    p.target_leading_zeros = difficulty_bits;
    return dhcm_core_calculate(&p, r);
}

static const pow_adapter_t argon2d_adapter = {
    .name     = "argon2d",
    .hash     = argon2d_hash,
    .get_cost = argon2d_get_cost,
};

const pow_adapter_t *pow_adapter_argon2d(void) { return &argon2d_adapter; }
