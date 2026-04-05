/* rng.h — RNG shim: maps rng_fill() to entropy_getrandom()
 *
 * pow/server/pow_challenge.c uses rng_fill(buf, len) to generate
 * random challenge IDs.  The actual OS RNG lives in seed/random/entropy.h.
 * This header bridges the two.
 */
#ifndef SEED_RNG_H
#define SEED_RNG_H

#include "../random/entropy.h"

/* rng_fill — fill buf with len cryptographically random bytes.
 * Returns 0 on success, -1 on failure (same contract as entropy_getrandom). */
static inline int rng_fill(void *buf, unsigned long len)
{
    return entropy_getrandom((uint8_t *)buf, (size_t)len);
}

#endif /* SEED_RNG_H */
