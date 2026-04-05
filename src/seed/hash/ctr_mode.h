/* ctr_mode.h — CTR-Mode Expansion for Hash-Based Seed Derivation (TIER 2)
 *
 * Simple counter-mode expansion using a hash algorithm:
 *   Block_i = Hash(seed || ctx_label || counter_i) for counter_i = 1, 2, 3, ...
 *   Output = concat(Block_1, Block_2, ...) truncated to desired length
 */
#ifndef SEED_CTR_MODE_H
#define SEED_CTR_MODE_H

#include <stdint.h>
#include <stddef.h>

typedef struct hash_ops_s hash_ops_t;

/* -------------------------------------------------------------------------
 * ctr_mode_expand — Perform CTR-mode hash-based expansion
 * -------------------------------------------------------------------------
 * Generates output bytes using counter-mode with a specified hash algorithm.
 *
 * Args:
 *   engine        — hash algorithm vtable pointer (must not be NULL)
 *   seed          — input seed material
 *   seed_len      — length of seed
 *   ctx_label     — domain separation label (can be NULL or empty)
 *   ctx_label_len — length of label
 *   out           — output buffer (caller-allocated)
 *   out_len       — number of bytes to generate (must be > 0)
 *
 * Returns:
 *   0   — success
 *  -1   — error (invalid argument, memory error, etc.)
 *
 * Algorithm:
 *   counter = 1
 *   generated = 0
 *   while (generated < out_len):
 *       block = Hash(seed || ctx_label || big_endian_counter)
 *       copy min(digest_size, out_len - generated) bytes to output
 *       counter++
 *       generated += bytes_copied
 */
int ctr_mode_expand(const hash_ops_t *engine,
                    const uint8_t *seed, size_t seed_len,
                    const char *ctx_label, size_t ctx_label_len,
                    uint8_t *out, size_t out_len);

#endif /* SEED_CTR_MODE_H */
