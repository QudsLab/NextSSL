/* pomelo.h — Pomelo password hashing stub (Plan 205)
 *
 * Source: Hongjun Wu (PHC submission, 2015), public domain.
 * Status: SOURCE NOT YET AVAILABLE — see note/plans/205_MISSING_ALGO_INTEGRATION.md
 *
 * To integrate:
 *   1. Obtain pomelo-v2.0.tar.gz from the PHC submissions archive.
 *   2. Copy pomelo.c and this header to src/hash/memory_hard/pomelo/
 *   3. Remove the #error pragma below.
 *
 * PHS interface per PHC specification:
 *   out      — output buffer (outlen bytes)
 *   in       — input (password), inlen bytes
 *   salt     — salt, saltlen bytes
 *   t_cost   — time cost (0-25, maps to 2^t_cost iterations)
 *   m_cost   — log2 of memory in KB (0-25)
 */
#ifndef POMELO_H
#define POMELO_H

#include <stddef.h>

#ifdef NEXTSSL_HAS_POMELO

int PHS(void *out, size_t outlen, const void *in, size_t inlen,
        const void *salt, size_t saltlen,
        unsigned int t_cost, unsigned int m_cost);

#else
/* Source not available — pomelo is conditionally compiled when NEXTSSL_HAS_POMELO is defined */
static inline int pomelo_not_available(void) { return -1; }
#endif

#endif /* POMELO_H */
