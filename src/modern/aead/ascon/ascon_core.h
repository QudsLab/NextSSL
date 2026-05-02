/* ascon_core.h — Ascon permutation core (SP 800-232)
 *
 * The Ascon family shares a single 320-bit (5×64-bit) state permutation.
 * Two round counts are used:
 *   pa = 12 rounds — full-round initialization / finalization
 *   pb =  6 rounds — data processing rounds (Ascon-128, Hash256, XOF128)
 *         8 rounds — Ascon-80pq (not implemented here)
 */
#ifndef NEXTSSL_ASCON_CORE_H
#define NEXTSSL_ASCON_CORE_H

#include <stdint.h>
#include <stddef.h>

/* 320-bit Ascon state: 5 × 64-bit lanes */
typedef struct {
    uint64_t x[5];
} ascon_state_t;

/* Apply the Ascon permutation for `rounds` rounds (6 or 12) */
void ascon_permute(ascon_state_t *s, int rounds);

/* Load/store helpers for big-endian 64-bit lanes */
uint64_t ascon_load64(const uint8_t *b);
void     ascon_store64(uint8_t *b, uint64_t v);

/* Pad a partial block: set bit at position len*8 from the MSB */
void ascon_pad(ascon_state_t *s, int lane, size_t len);

#endif /* NEXTSSL_ASCON_CORE_H */
