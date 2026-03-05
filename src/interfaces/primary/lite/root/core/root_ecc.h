/**
 * @file root/core/root_ecc.h (Lite)
 * @brief NextSSL Root Lite -- Explicit ECC interface.
 *
 * Lite build provides: Ed25519 (sign/verify), X25519 (key exchange).
 * No X448, Ristretto255, Elligator2 in lite build.
 *
 * Ed25519 key layout:
 *   pk  = 32 bytes (public key)
 *   sk  = 64 bytes: seed[32] || pk[32]
 *   sig = 64 bytes
 *
 * X25519 key layout:
 *   private_key = 32 bytes (scalar, clamped internally)
 *   public_key  = 32 bytes (Montgomery u-coordinate)
 *   shared_sec  = 32 bytes
 *
 * @version 0.0.1-beta
 */

#ifndef NEXTSSL_LITE_ROOT_ECC_H
#define NEXTSSL_LITE_ROOT_ECC_H

#include <stddef.h>
#include <stdint.h>
#include "../../../../../config.h"  /* NEXTSSL_API */

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * Ed25519 -- signing
 * ========================================================================== */

NEXTSSL_API int nextssl_root_ecc_ed25519_keygen(uint8_t pk[32], uint8_t sk[64]);

NEXTSSL_API int nextssl_root_ecc_ed25519_sign(const uint8_t sk[64],
                                               const uint8_t *msg, size_t mlen,
                                               uint8_t sig[64]);

NEXTSSL_API int nextssl_root_ecc_ed25519_verify(const uint8_t pk[32],
                                                 const uint8_t *msg, size_t mlen,
                                                 const uint8_t sig[64]);

/* ==========================================================================
 * X25519 -- key exchange
 * ========================================================================== */

NEXTSSL_API int nextssl_root_ecc_x25519_keygen(uint8_t sk[32], uint8_t pk[32]);

NEXTSSL_API int nextssl_root_ecc_x25519_exchange(const uint8_t sk[32],
                                                  const uint8_t their_pk[32],
                                                  uint8_t shared[32]);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_LITE_ROOT_ECC_H */
