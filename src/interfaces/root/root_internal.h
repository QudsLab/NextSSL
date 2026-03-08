/**
 * @file root/root_internal.h
 * @brief Internal helpers shared across root sub-modules (NOT public API).
 *
 * Include only from root/ implementation (.c) files, never from outside.
 */

#ifndef NEXTSSL_ROOT_INTERNAL_H
#define NEXTSSL_ROOT_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef NEXTSSL_BUILDING_DLL
#define NEXTSSL_BUILDING_DLL
#endif
#include "../../config.h"  /* NEXTSSL_API */

/* -------------------------------------------------------------------------
 * CSPRNG helper -- fills buf with len cryptographically random bytes.
 * Returns 0 on success, -1 on failure.
 * Delegates to the unified seed/rng layer (rng_fill) so the entire library
 * shares one randomness path instead of duplicating per-platform OS calls.
 * ---------------------------------------------------------------------- */
#include "../../seed/rng/rng.h"
static inline int _root_rand(uint8_t *buf, size_t len) {
    return rng_fill(buf, len);
}

#endif /* NEXTSSL_ROOT_INTERNAL_H */