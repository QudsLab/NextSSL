/* seed_derive_random.h - TIER 1 Entry Point for Random Derivation
 *
 * Simple interface to generate random bytes from the OS RNG.
 */
#ifndef SEED_DERIVE_RANDOM_H
#define SEED_DERIVE_RANDOM_H

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * seed_derive_random - Generate random bytes (PATH 1)
 * -------------------------------------------------------------------------*/
int seed_derive_random(uint8_t *out, size_t out_len);

/* -------------------------------------------------------------------------
 * seed_derive_random_label - Generate bytes with optional UDBF override label
 * -------------------------------------------------------------------------*/
int seed_derive_random_label(const char *label, uint8_t *out, size_t out_len);

#endif /* SEED_DERIVE_RANDOM_H */
