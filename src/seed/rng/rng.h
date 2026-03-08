#ifndef NEXTSSL_SEED_RNG_H
#define NEXTSSL_SEED_RNG_H

#include <stddef.h>
#include <stdint.h>

/*
 * rng.h — OS-sourced random bytes (non-deterministic)
 *
 * Platform dispatch:
 *   Windows  : BCryptGenRandom
 *   Linux    : getrandom(2) with GRND_RANDOM fallback to /dev/urandom
 *   macOS/BSD: arc4random_buf
 *
 * These functions NEVER call the DRBG. They are the only entry point for
 * KEYGEN_RANDOM mode in Task 104 (keygen_new_random).
 *
 * Return: 0 on success, -1 on OS-level failure.
 */

int rng_fill   (uint8_t *out, size_t len);
int rng_uint32 (uint32_t *out);
int rng_uint64 (uint64_t *out);

#endif /* NEXTSSL_SEED_RNG_H */
