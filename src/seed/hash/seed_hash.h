#ifndef NEXTSSL_SEED_HASH_H
#define NEXTSSL_SEED_HASH_H

#include <stddef.h>
#include <stdint.h>

/*
 * seed_hash.h — Hash-based key derivation (SHA-512 CTR mode)
 *
 * Strategy: SHA-512(seed || ctx || BE32(counter))
 *
 * Used when:
 *   - Caller already holds a high-entropy secret (not a password)
 *   - Reproducible output without full DRBG state is acceptable
 *   - Multiple independent keys from one master are needed (via counter)
 *
 * Minimum seed_len: 32 bytes. Shorter inputs are accepted but weaken security.
 * ctx may be NULL (no domain label applied).
 * out_len may be larger than 64 — output is built by incrementing the counter.
 *
 * Return: 0 on success, -1 on invalid arguments.
 */
int seed_hash_derive(const uint8_t *seed,   size_t seed_len,
                     const uint8_t *ctx,    size_t ctx_len,
                     uint8_t       *out,    size_t out_len);

#endif /* NEXTSSL_SEED_HASH_H */
