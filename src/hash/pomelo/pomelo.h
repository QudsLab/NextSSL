/* pomelo.h — Pomelo password hashing (Plan 205)
 *
 * Source: Hongjun Wu (PHC submission, 2015), public domain.
 * Status: implemented locally — bundled PHC submission source.
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

int PHS(void *out, size_t outlen, const void *in, size_t inlen,
        const void *salt, size_t saltlen,
        unsigned int t_cost, unsigned int m_cost);

#endif /* POMELO_H */
