/* seed_core.h — TIER 2 Main Dispatcher for Hash-Based Derivation (TIER 2)
 *
 * Central entry point for deterministic seed derivation via CTR-mode expansion.
 * Integrates TIER 1 (random), TIER 2 (hash), and TIER 3 (UDBF override).
 */
#ifndef SEED_CORE_H
#define SEED_CORE_H

#include "seed_types.h"
#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * seed_hash_derive — TIER 2 Main Dispatcher
 * -------------------------------------------------------------------------
 * Performs deterministic seed derivation via CTR-mode hash expansion.
 * Checks TIER 3 (UDBF) override first; if active, uses test vector instead.
 *
 * Args:
 *   cfg         — hash configuration (engine + ctx_label)
 *   seed        — input seed bytes (salt/entropy source)
 *   seed_len    — length of seed
 *   out         — output buffer (caller-allocated)
 *   out_len     — number of bytes to generate
 *
 * Returns:
 *   0   — success, output filled with derived bytes
 *  -1   — error (invalid argument, UDBF error, CTR overflow, etc.)
 *
 * Notes:
 *   - If cfg->engine is NULL, defaults to SHA-512
 *   - If cfg->ctx_label is NULL or empty, no labels are used
 *   - Results are deterministic: same seed + label → same output
 *   - Output buffer must be >= out_len bytes
 *   - Temporary buffers are securely wiped before return
 */
int seed_hash_derive(const seed_hash_config_t *cfg,
                     const uint8_t *seed, size_t seed_len,
                     uint8_t *out, size_t out_len);

#endif /* SEED_CORE_H */
