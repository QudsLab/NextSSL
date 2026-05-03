/*
 * Catena-BRG (Bit-Reversal Graph) default variant.
 *
 * Provides the extern constants and Flap() function required by catena.c.
 * Uses BRG (Bit-Reversal Graph) as the default memory-access pattern.
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "catena.h"
#include "catena-helpers.h"
#include "hash.h"

/* ── Default parameters for Catena-BRG ──────────────────────── */
const uint8_t LAMBDA     = 2;
const uint8_t GARLIC     = 21;    /* 2^21 = 2 MB */
const uint8_t MIN_GARLIC = 21;
const uint8_t VERSION_ID[] = "Butterfly-Full";

/* ── Bit-reversal index ─────────────────────────────────────── */
static uint64_t reverse(uint64_t x, const uint8_t n)
{
    uint64_t r = 0;
    for (uint8_t i = 0; i < n; i++) {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    return r;
}

/* ── Flap: BRG memory-hard graph traversal ──────────────────── */
void Flap(const uint8_t x[H_LEN], const uint8_t lambda,
          const uint8_t garlic, const uint8_t *salt,
          const uint8_t saltlen, uint8_t h[H_LEN])
{
    const uint64_t c = UINT64_C(1) << garlic;
    uint8_t *r = (uint8_t *)malloc(c * H_LEN);
    if (!r) return;

    initmem(x, c, r);
    catena_gamma(garlic, salt, saltlen, r);

    for (uint8_t k = 0; k < lambda; k++) {
        /* BRG phase */
        __ResetState();
        for (uint64_t i = 1; i < c; i++) {
            uint64_t ri = reverse(i, garlic);
            if (ri > i) {
                XOR(r + i * H_LEN, r + ri * H_LEN, r + i * H_LEN);
                __HashFast((int)i, r + (i - 1) * H_LEN, r + i * H_LEN, r + i * H_LEN);
            } else {
                __HashFast((int)i, r + (i - 1) * H_LEN, r + i * H_LEN, r + i * H_LEN);
            }
        }
    }

    memcpy(h, r + (c - 1) * H_LEN, H_LEN);
    free(r);
}
