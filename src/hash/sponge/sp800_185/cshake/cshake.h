/* cshake.h — cSHAKE-128 and cSHAKE-256 (NIST SP 800-185 §3)
 *
 * cSHAKE is a customizable SHAKE variant.  It absorbs a function-name
 * string N and a customization string S before any user data:
 *
 *   cSHAKE(X, L, N, S) =
 *       KECCAK[2L](bytepad(encode_string(N) || encode_string(S), rate)
 *                  || X || 0x04, L)
 *
 * When N="" and S="", cSHAKE(X, L, "", "") == SHAKE(X, L).
 */
#ifndef NEXTSSL_HASH_CSHAKE_H
#define NEXTSSL_HASH_CSHAKE_H

#include <stdint.h>
#include <stddef.h>
#include "shake.h"

typedef struct {
    SHAKE_CTX shake;
    int       pure_shake; /* 1 when N=="" && S=="" → use 0x1F padding */
} CSHAKE_CTX;

/* Streaming interface */
void cshake128_init(CSHAKE_CTX *ctx,
                    const uint8_t *N, size_t Nlen,
                    const uint8_t *S, size_t Slen);

void cshake256_init(CSHAKE_CTX *ctx,
                    const uint8_t *N, size_t Nlen,
                    const uint8_t *S, size_t Slen);

void cshake_update(CSHAKE_CTX *ctx, const uint8_t *data, size_t len);

/* Finalise and squeeze outlen bytes into out.  May only be called once. */
void cshake_squeeze(CSHAKE_CTX *ctx, uint8_t *out, size_t outlen);

/* One-shot convenience wrappers
 * NOTE: named _oneshot to avoid collision with the PQC-layer cshake128/cshake256
 * symbols defined in src/pqc/common/sp800-185.c which use a different signature. */
void cshake128_oneshot(const uint8_t *N, size_t Nlen,
                       const uint8_t *S, size_t Slen,
                       const uint8_t *data, size_t dlen,
                       uint8_t *out, size_t outlen);

void cshake256_oneshot(const uint8_t *N, size_t Nlen,
                       const uint8_t *S, size_t Slen,
                       const uint8_t *data, size_t dlen,
                       uint8_t *out, size_t outlen);

#endif /* NEXTSSL_HASH_CSHAKE_H */
