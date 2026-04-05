/* seed_derive_random.h — TIER 1 Entry Point for Random Derivation
 *
 * Simple interface to generate random bytes from the OS RNG.
 */
#ifndef SEED_DERIVE_RANDOM_H
#define SEED_DERIVE_RANDOM_H

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * seed_derive_random — Generate random bytes (PATH 1)
 * -------------------------------------------------------------------------
 * Generates out_len bytes of random data from the OS cryptographic RNG.
 *
 * Args:
 *   out     — output buffer (caller-allocated)
 *   out_len — number of bytes to generate (must be > 0)
 *
 * Returns:
 *   0   — success, out filled with random bytes
 *  -1   — error (RNG unavailable or invalid argument)
 */
int seed_derive_random(uint8_t *out, size_t out_len);

#endif /* SEED_DERIVE_RANDOM_H */
