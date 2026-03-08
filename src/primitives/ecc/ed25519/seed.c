#include "ed25519.h"

#ifndef ED25519_NO_SEED

#include "../../../../seed/rng/rng.h"

int ed25519_create_seed(unsigned char *seed) {
    /* Delegate to the unified OS CSPRNG (rng_fill). Returns 0 on success,
     * 1 on failure to match the original convention used by callers. */
    return (rng_fill(seed, 32) == 0) ? 0 : 1;
}

#endif
