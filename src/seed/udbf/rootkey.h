#ifndef NEXTSSL_COMMON_ROOTKEY_H
#define NEXTSSL_COMMON_ROOTKEY_H

#include <stddef.h>
#include <stdint.h>

/*
 * Root-Key Orchestrator
 *
 * Single entry-point for all key-material generation across NextSSL.
 * Resolves the randomness source in strict priority order and applies
 * domain-separation via HKDF labelling.
 *
 * Priority order (highest to lowest):
 *   1. ROOTKEY_MODE_UDBF  — deterministic UDBF feed (testing / KAT vectors)
 *   2. ROOTKEY_MODE_SEED  — caller-supplied seed + HKDF domain separation
 *   3. ROOTKEY_MODE_DRBG  — seeded HMAC-DRBG (PQCrypto/common/drbg)
 *   4. ROOTKEY_MODE_OSRNG — OS entropy (only for non-deterministic uses)
 *
 * Security contract:
 *   - If mode == ROOTKEY_MODE_UDBF and UDBF is not active, returns -1.
 *     Never falls back to OS RNG silently.
 *   - If mode == ROOTKEY_MODE_SEED and seed is NULL/empty, returns -1.
 *   - Output buffer is never partially filled: on any error the buffer is
 *     left zeroed and a negative code is returned.
 *   - Callers must wipe out[] after use for sensitive key material.
 */

typedef enum {
    ROOTKEY_MODE_UDBF  = 0,  /* domain-separated UDBF feed                   */
    ROOTKEY_MODE_SEED  = 1,  /* explicit seed + HKDF label                   */
    ROOTKEY_MODE_DRBG  = 2,  /* seeded global HMAC-DRBG                      */
    ROOTKEY_MODE_OSRNG = 3,  /* OS entropy (not for deterministic key-gen)   */
} rootkey_mode_t;

/*
 * rootkey_get - Derive key material.
 *
 * @mode:     Source selection (see rootkey_mode_t).
 * @label:    Non-NULL domain-separation label (e.g. "mlkem768-keypair").
 *            Used as HKDF `info` for ROOTKEY_MODE_UDBF and ROOTKEY_MODE_SEED.
 * @seed:     Caller seed (required for ROOTKEY_MODE_SEED; ignored otherwise).
 * @seed_len: Length of @seed.
 * @out:      Output buffer for key material.
 * @out_len:  Number of bytes to produce.
 *
 * @return:  0 on success, negative on failure.
 */
int rootkey_get(rootkey_mode_t  mode,
                const char     *label,
                const uint8_t  *seed,
                size_t          seed_len,
                uint8_t        *out,
                size_t          out_len);

#endif /* NEXTSSL_COMMON_ROOTKEY_H */
