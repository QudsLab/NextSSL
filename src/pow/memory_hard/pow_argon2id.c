/* pow_argon2id.c — PoW adapter: argon2id */
#include "../core/pow_types.h"
#include "../dhcm/dhcm_core.h"
#include "../../hash/interface/hash_registry.h"
#include <stdint.h>
#include <stddef.h>

#define HASH_OPS_CTX_MAX 2048

static int argon2id_hash(const uint8_t *in, size_t len,
                          const void *params, uint8_t *out) {
    (void)params;
    const hash_ops_t *h = hash_lookup("argon2id");
    if (!h) return -1;
    uint8_t ctx[HASH_OPS_CTX_MAX];
    h->init(ctx);
    h->update(ctx, in, len);
    h->final(ctx, out);
    return 0;
}

static int argon2id_get_cost(uint32_t difficulty_bits, DHCMResult *r) {
    DHCMParams p = {0};
    p.algorithm            = DHCM_ARGON2ID;
    p.difficulty_model     = DHCM_DIFFICULTY_ITERATION_BASED;
    p.target_leading_zeros = difficulty_bits;
    /* defaults used — dhcm_core.c applies t=2, m=65536, p=1 */
    return dhcm_core_calculate(&p, r);
}

static const pow_adapter_t argon2id_adapter = {
    .name     = "argon2id",
    .hash     = argon2id_hash,
    .get_cost = argon2id_get_cost,
};

const pow_adapter_t *pow_adapter_argon2id(void) { return &argon2id_adapter; }
