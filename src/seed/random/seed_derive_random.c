/* seed_derive_random.c — TIER 1 Entry Point for Random Derivation */
#include "seed_derive_random.h"
#include "entropy.h"

/* -------------------------------------------------------------------------
 * seed_derive_random — TIER 1: Generate random bytes
 * -------------------------------------------------------------------------*/
int seed_derive_random(uint8_t *out, size_t out_len)
{
    if (!out || out_len == 0) {
        return -1;  /* Invalid arguments */
    }

    if (!entropy_available()) {
        return -1;  /* OS RNG not available on this platform */
    }

    return entropy_getrandom(out, out_len);
}
