#include "ed25519.h"

#ifndef ED25519_NO_SEED

#include "../../../seed/rng/rng.h"

int ed25519_create_seed(unsigned char *seed) {
    /*
     * GAP-6: Explicit routing note.
     *
     * This function is the ONLY entry point for Ed25519 seed generation.
     * It MUST delegate to rng_fill() — never to rand(), getrandom() directly,
     * or any other OS call — so that all platform-specific CSPRNG dispatch
     * stays in seed/rng/rng.c.
     *
     * Returns 0 on success, 1 on failure (matches original ed25519 convention).
     */
    return (rng_fill(seed, 32) == 0) ? 0 : 1;
}

#endif
