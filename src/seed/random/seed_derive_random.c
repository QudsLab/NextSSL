/* seed_derive_random.c — TIER 1 Entry Point for Random Derivation */
#include "seed_derive_random.h"
#include "entropy.h"
#include "../udbf/udbf.h"

/* -------------------------------------------------------------------------
 * seed_derive_random — TIER 1: Generate random bytes
 * -------------------------------------------------------------------------*/
int seed_derive_random(uint8_t *out, size_t out_len)
{
    return seed_derive_random_label(NULL, out, out_len);
}

int seed_derive_random_label(const char *label, uint8_t *out, size_t out_len)
{
    if (!out || out_len == 0) {
        return -1;  /* Invalid arguments */
    }

    if (seed_udbf_is_active()) {
        const char *ctx = (label && label[0] != '\0') ? label : "";
        return udbf_read(ctx, out, out_len) == (int)out_len ? 0 : -1;
    }

    if (!entropy_available()) {
        return -1;  /* OS RNG not available on this platform */
    }

    return entropy_getrandom(out, out_len);
}
