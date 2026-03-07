/**
 * @file root/core/root_ecc.c (Lite)
 * @brief NextSSL Root Lite -- ECC implementations (Ed25519 + X25519).
 */

#ifndef NEXTSSL_BUILDING_DLL
#define NEXTSSL_BUILDING_DLL
#endif

#include "root_ecc.h"
#include "../root_internal.h"
#include "../../../../../primitives/ecc/ed25519/ed25519.h"

/* ==========================================================================
 * Ed25519
 * ========================================================================== */

NEXTSSL_API int nextssl_root_ecc_ed25519_keygen(uint8_t pk[32], uint8_t sk[64]) {
    if (!pk || !sk) return -1;
    uint8_t seed[32];
    if (_root_rand(seed, 32) != 0) return -1;
    ed25519_create_keypair(pk, sk, seed);
    /* embed pk at sk+32 for sign convenience */
    __builtin_memcpy(sk + 32, pk, 32);
    return 0;
}

NEXTSSL_API int nextssl_root_ecc_ed25519_sign(const uint8_t sk[64],
                                               const uint8_t *msg, size_t mlen,
                                               uint8_t sig[64]) {
    if (!sk || !sig) return -1;
    if (mlen > 0 && !msg) return -1;
    /* sk layout: seed[32]||pk[32]; ed25519_sign expects (sig, msg, mlen, pk, sk) */
    ed25519_sign(sig, msg, mlen, sk + 32, sk);
    return 0;
}

NEXTSSL_API int nextssl_root_ecc_ed25519_verify(const uint8_t pk[32],
                                                 const uint8_t *msg, size_t mlen,
                                                 const uint8_t sig[64]) {
    if (!pk || !sig) return -1;
    if (mlen > 0 && !msg) return -1;
    return ed25519_verify(sig, msg, mlen, pk) == 1 ? 1 : 0;
}

/* ==========================================================================
 * X25519
 * ========================================================================== */

NEXTSSL_API int nextssl_root_ecc_x25519_keygen(uint8_t sk[32], uint8_t pk[32]) {
    if (!sk || !pk) return -1;
    uint8_t seed[32];
    uint8_t sk_full[64];
    if (_root_rand(seed, 32) != 0) return -1;
    /* Derive the Ed25519 keypair from seed.
     * pk = Edwards Y public key (compatible with ed25519_key_exchange).
     * sk = first 32 bytes of the SHA-512 expanded key (the clamped scalar). */
    ed25519_create_keypair(pk, sk_full, seed);
    __builtin_memcpy(sk, sk_full, 32);
    return 0;
}

NEXTSSL_API int nextssl_root_ecc_x25519_exchange(const uint8_t sk[32],
                                                  const uint8_t their_pk[32],
                                                  uint8_t shared[32]) {
    if (!sk || !their_pk || !shared) return -1;
    ed25519_key_exchange(shared, their_pk, sk);
    return 0;
}
