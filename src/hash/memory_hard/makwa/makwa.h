/* makwa.h — Makwa password hashing stub (Plan 205)
 *
 * Source: Thomas Pornin (PHC submission, 2015).
 * Licence: MIT (see makwa-java/LICENSE in the original distribution).
 * Status: SOURCE NOT YET AVAILABLE — see note/plans/205_MISSING_ALGO_INTEGRATION.md
 *
 * Makwa is based on modular squaring in a large integer ring (like RSA),
 * requiring a 2048-bit or 4096-bit modulus.
 *
 * To integrate:
 *   1. Obtain the Makwa reference C implementation from:
 *        https://www.bolet.org/makwa/
 *   2. Copy makwa.c/makwa.h to src/hash/memory_hard/makwa/
 *   3. Remove the conditional guard below.
 *
 * PHS-like interface:
 *   int makwa_hash(const uint8_t *password, size_t passlen,
 *                  const uint8_t *salt, size_t saltlen,
 *                  const makwa_params_t *params,
 *                  uint8_t *out, size_t outlen);
 */
#ifndef MAKWA_H
#define MAKWA_H

#include <stddef.h>
#include <stdint.h>

#ifdef NEXTSSL_HAS_MAKWA
/* Forward declaration — actual types defined in makwa.c */
int makwa_hash(const uint8_t *password, size_t passlen,
               const uint8_t *salt, size_t saltlen,
               uint32_t work_factor,
               uint8_t *out, size_t outlen);
#else
static inline int makwa_not_available(void) { return -1; }
#endif

#endif /* MAKWA_H */
