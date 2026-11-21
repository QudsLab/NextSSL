
#ifndef PRNG_H
#define PRNG_H

#include <stdint.h>
#include "hash.h"

#include "fips202.h"
typedef keccak_state mirath_prng_t;

#define shake_init shake128_init
#define shake_absorb shake128_absorb
#define shake_finalize shake128_finalize
#define shake_squeeze shake128_squeeze
#define shake_256 shake256

/* Initialize 'prng' from 'salt' and 'seed'.
 * If 'salt == NULL' then 'salt' is ignored.
 * If 'seed == NULL' then 'seed' is ignored. */
void mirath_prng_init(mirath_prng_t *prng, const uint8_t *salt, const seed_t seed, uint32_t seed_size_bytes);

/* Write 'length' pseudorandom bytes over 'target',
 * update the internal state of 'prng'. */
void mirath_prng(mirath_prng_t *prng, void *target, size_t length);

#endif
