/* turboshake.h — TurboSHAKE: KeccakP-1600 with reduced rounds
 *
 * TurboSHAKE is the reduced-round variant of SHAKE used as the inner
 * permutation for KangarooTwelve (12 rounds) and MarsupilamiFourteen
 * (14 rounds).  Full Keccak-f uses 24 rounds; TurboSHAKE uses fewer.
 *
 * API mirrors shake.h so callers can treat this as a drop-in sponge.
 *
 * References:
 *   - KangarooTwelve: RFC 9285
 *   - MarsupilamiFourteen: https://keccak.team/marsupilami.html
 *   - KeccakP-1600: NIST FIPS 202 Appendix B
 */
#ifndef NEXTSSL_HASH_TURBOSHAKE_H
#define NEXTSSL_HASH_TURBOSHAKE_H

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Context
 * -------------------------------------------------------------------------
 * sizeof(TURBOSHAKE_CTX) = 25*8 + 4 + 1 + 3pad + 8 + 1 + 3pad = ~232 bytes
 * Fits comfortably inside HASH_OPS_CTX_MAX (2048).
 * -------------------------------------------------------------------------*/
typedef struct {
    uint64_t state[25];  /* KeccakP-1600 lane state (little-endian)        */
    size_t   rate;       /* sponge rate in bytes (168 for K12, 136 for M14)*/
    uint8_t  buf[200];   /* input buffer up to rate bytes                   */
    size_t   buf_len;    /* bytes currently in buf                          */
    int      finalized;  /* 1 after squeeze phase begins                    */
    int      rounds;     /* number of Keccak rounds (12 or 14)              */
} TURBOSHAKE_CTX;

/* Initialise context.
 *   rate   — sponge rate in bytes: 168 for TurboSHAKE128, 136 for TurboSHAKE256
 *   rounds — permutation round count: 12 (K12) or 14 (M14) */
void turboshake_init(TURBOSHAKE_CTX *ctx, size_t rate, int rounds);

/* Absorb data into the sponge. May be called multiple times. */
void turboshake_update(TURBOSHAKE_CTX *ctx, const uint8_t *data, size_t len);

/* Finalise absorption with the given domain separation byte, then prepare
 * for squeezing.  domain_sep = 0x07 for TurboSHAKE, 0x0B for K12/M14
 * inner leaves, 0x06 for K12/M14 final node. */
void turboshake_final(TURBOSHAKE_CTX *ctx, uint8_t domain_sep);

/* Squeeze output bytes from the sponge.  May be called multiple times
 * after turboshake_final(). */
void turboshake_squeeze(TURBOSHAKE_CTX *ctx, uint8_t *out, size_t outlen);

/* Convenience: one-shot absorb + finalise + squeeze. */
void turboshake128_oneshot(const uint8_t *data, size_t dlen,
                           uint8_t domain_sep,
                           uint8_t *out, size_t outlen);

void turboshake256_oneshot(const uint8_t *data, size_t dlen,
                           uint8_t domain_sep,
                           uint8_t *out, size_t outlen);

#endif /* NEXTSSL_HASH_TURBOSHAKE_H */
