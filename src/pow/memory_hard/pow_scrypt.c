/* pow_scrypt.c — PoW adapter: scrypt */
#include "../core/pow_types.h"
#include "../dhcm/dhcm_core.h"
#include "../../hash/interface/hash_registry.h"
#include <stdint.h>
#include <stddef.h>

#define HASH_OPS_CTX_MAX 2048

static int scrypt_hash(const uint8_t *in, size_t len,
                        const void *params, uint8_t *out) {
    (void)params;
    const hash_ops_t *h = hash_lookup("scrypt");
    if (!h) return -1;
    uint8_t ctx[HASH_OPS_CTX_MAX];
    h->init(ctx);
    h->update(ctx, in, len);
    h->final(ctx, out);
    return 0;
}

static int scrypt_get_cost(uint32_t difficulty_bits, DHCMResult *r) {
    DHCMParams p = {0};
    p.algorithm            = DHCM_SCRYPT;
    p.difficulty_model     = DHCM_DIFFICULTY_ITERATION_BASED;
    p.target_leading_zeros = difficulty_bits;
    /* defaults: N=16384, r=8, p=1 applied in dhcm_core.c */
    return dhcm_core_calculate(&p, r);
}

static const pow_adapter_t scrypt_adapter = {
    .name     = "scrypt",
    .hash     = scrypt_hash,
    .get_cost = scrypt_get_cost,
};

const pow_adapter_t *pow_adapter_scrypt(void) { return &scrypt_adapter; }
