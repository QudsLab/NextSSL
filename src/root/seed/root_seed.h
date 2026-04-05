/* root_seed.h — Exported Seed / Key Derivation API (Plan 405)
 *
 * Two derivation paths:
 *   PATH 1 — nextssl_seed_random():  OS RNG bytes (TIER 1)
 *   PATH 2 — nextssl_seed_derive():  Deterministic CTR-mode derivation (TIER 2)
 *
 * Test mode:
 *   nextssl_seed_udbf_feed():  Load known-answer test vector (TIER 3)
 *   nextssl_seed_udbf_wipe():  Clear test vector and return to normal mode
 */
#ifndef ROOT_SEED_H
#define ROOT_SEED_H

#include <stddef.h>
#include <stdint.h>
#include "../nextssl_export.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * nextssl_seed_random — PATH 1: Random bytes from OS RNG
 * -------------------------------------------------------------------------
 * Returns 0 on success, -1 on error.
 */
NEXTSSL_API int nextssl_seed_random(uint8_t *out, size_t len);

/* -------------------------------------------------------------------------
 * nextssl_seed_derive — PATH 2: Deterministic CTR-mode derivation
 * -------------------------------------------------------------------------
 * algo      — hash algorithm name (NULL or "" = default "sha512")
 * label     — domain separation label (NULL or "" = no label)
 * seed      — input seed bytes
 * seed_len  — length of seed
 * out       — caller-allocated output buffer
 * out_len   — number of bytes to derive (max 1 MB)
 *
 * Result is deterministic: same algo + label + seed → same output.
 * Returns 0 on success, -1 on error.
 */
NEXTSSL_API int nextssl_seed_derive(
    const char    *algo,
    const char    *label,
    const uint8_t *seed,
    size_t         seed_len,
    uint8_t       *out,
    size_t         out_len);

/* -------------------------------------------------------------------------
 * nextssl_seed_udbf_feed — TIER 3: Load test vector data
 * -------------------------------------------------------------------------
 * For testing only. Subsequent calls to nextssl_seed_derive() will return
 * bytes from this buffer (keyed by label) instead of performing derivation.
 * Returns 0 on success, negative on error.
 */
NEXTSSL_API int nextssl_seed_udbf_feed(const uint8_t *data, size_t len);

/* -------------------------------------------------------------------------
 * nextssl_seed_udbf_wipe — TIER 3: Clear test vector and reset
 */
NEXTSSL_API void nextssl_seed_udbf_wipe(void);

#ifdef __cplusplus
}
#endif

#endif /* ROOT_SEED_H */
