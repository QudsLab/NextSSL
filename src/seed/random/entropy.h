/* entropy.h — OS RNG Interface (TIER 1)
 *
 * Platform-specific cryptographic RNG wrapper:
 *   - Windows: BCryptGenRandom()
 *   - Linux: getrandom()
 *   - macOS: arc4random_buf()
 */
#ifndef SEED_ENTROPY_H
#define SEED_ENTROPY_H

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * entropy_getrandom — Get random bytes from the OS RNG
 * -------------------------------------------------------------------------
 * Returns:
 *   0  — success, out filled with random bytes
 *  -1  — error (RNG unavailable or failed)
 */
int entropy_getrandom(uint8_t *out, size_t out_len);

/* -------------------------------------------------------------------------
 * entropy_available — Check if OS RNG is available
 * -------------------------------------------------------------------------
 * Returns:
 *   1  — yes, RNG available
 *   0  — no, RNG not available on this platform
 */
int entropy_available(void);

#endif /* SEED_ENTROPY_H */
