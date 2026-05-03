/* sm3_ops.c — SM3 hash_ops_t + hash_registry registration  */
#include "sm3.h"
#include "../interface/hash_registry.h"
#include <stdint.h>

static void sm3_ops_init  (void *c) { sm3_init((SM3_CTX *)c); }
static void sm3_ops_update(void *c, const uint8_t *d, size_t l) { sm3_update((SM3_CTX *)c, d, l); }
static void sm3_ops_final (void *c, uint8_t *out) { sm3_final((SM3_CTX *)c, out); }

const hash_ops_t sm3_ops = {
    .name        = "sm3",
    .digest_size = SM3_DIGEST_LENGTH,
    .block_size  = SM3_BLOCK_LEN,
    .usage_flags = HASH_USAGE_ALL,
    .init        = sm3_ops_init,
    .update      = sm3_ops_update,
    .final       = sm3_ops_final,
    .wu_per_eval = 2.0,
    .mu_per_eval = 0.0,
    .parallelism = 1
};
