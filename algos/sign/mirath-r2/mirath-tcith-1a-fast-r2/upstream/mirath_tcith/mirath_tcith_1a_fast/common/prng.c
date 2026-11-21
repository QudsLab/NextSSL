#include <string.h>
#include "prng.h"

void mirath_prng_init(mirath_prng_t *prng, const uint8_t *salt, const seed_t seed, const uint32_t seed_size_bytes) {
    uint8_t input[MIRATH_PARAM_SALT_BYTES + seed_size_bytes];
    memset(input, 0, MIRATH_PARAM_SALT_BYTES + seed_size_bytes);
    uint32_t length = 0;

    shake_init(prng);

    /* Set 'buffer = salt | seed'. */
    if (salt != NULL) {
        memcpy(input, salt, MIRATH_PARAM_SALT_BYTES);
        length = MIRATH_PARAM_SALT_BYTES;
    }

    if (seed != NULL){
        memcpy(input + length, seed, seed_size_bytes);
        length += seed_size_bytes;
    }

    shake_absorb(prng, input, length);
    shake_finalize(prng);
}

void mirath_prng(mirath_prng_t *prng, void *target, size_t length) {
    shake_squeeze((uint8_t*) target, length, prng);
}
