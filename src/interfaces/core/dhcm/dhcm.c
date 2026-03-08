/**
 * @file core/dhcm/dhcm.c
 * @brief Layer 2 (base) DHCM/key-exchange shim — delegates to root layer.
 *
 * Naming note: nextssl_base_* prefix per NEXTSSL_BASE_API in visibility.h,
 * directory is interfaces/core/. Same pre-existing inconsistency as sign.c.
 *
 * Argument-order differences between root and base APIs are handled here
 * so callers in main/full/ see the base convention consistently:
 *   base exchange: (shared_secret, our_sk, their_pk)
 *   root exchange: (my_sk, their_pk, shared_secret)
 *
 * Delegation map:
 *   nextssl_base_dhcm_x25519_*       → nextssl_root_ecc_x25519_*
 *   nextssl_base_dhcm_x448_*         → nextssl_root_ecc_x448_* (full only)
 *   nextssl_base_dhcm_ml_kem_768_*   → nextssl_root_pqc_kem_mlkem768_*
 *   nextssl_base_dhcm_p256_*         → stub -1 (no root P-256 layer yet)
 */

#include "dhcm.h"
#include "../../root/pqc/root_pqc_kem.h"
#include "../../root/core/root_ecc.h"
#include "../../root/core/root_ecc.h"
#include "../../root/pqc/root_pqc_kem.h"

/* =========================================================================
 * X25519
 * ====================================================================== */

int nextssl_base_dhcm_x25519_keypair(uint8_t public_key[32],
                                      uint8_t secret_key[32])
{
    if (!public_key || !secret_key) return -1;
    return nextssl_root_ecc_x25519_keygen(public_key, secret_key);
}

int nextssl_base_dhcm_x25519_exchange(uint8_t shared_secret[32],
                                       const uint8_t our_secret_key[32],
                                       const uint8_t their_public_key[32])
{
    if (!shared_secret || !our_secret_key || !their_public_key) return -1;
    /* root arg order: (my_sk, their_pk, ss); base is (ss, our_sk, their_pk) */
    return nextssl_root_ecc_x25519_exchange(our_secret_key, their_public_key,
                                             shared_secret);
}

/* =========================================================================
 * X448 (full build only — root guards it with #ifndef NEXTSSL_BUILD_LITE)
 * ====================================================================== */

#ifndef NEXTSSL_BUILD_LITE

int nextssl_base_dhcm_x448_keypair(uint8_t public_key[56],
                                    uint8_t secret_key[56])
{
    if (!public_key || !secret_key) return -1;
    return nextssl_root_ecc_x448_keygen(public_key, secret_key);
}

int nextssl_base_dhcm_x448_exchange(uint8_t shared_secret[56],
                                     const uint8_t our_secret_key[56],
                                     const uint8_t their_public_key[56])
{
    if (!shared_secret || !our_secret_key || !their_public_key) return -1;
    /* root arg order: (my_sk, their_pk, ss); base is (ss, our_sk, their_pk) */
    return nextssl_root_ecc_x448_exchange(our_secret_key, their_public_key,
                                          shared_secret);
}

#else  /* NEXTSSL_BUILD_LITE */

int nextssl_base_dhcm_x448_keypair(uint8_t pk[56], uint8_t sk[56])
    { (void)pk; (void)sk; return -1; }
int nextssl_base_dhcm_x448_exchange(uint8_t ss[56],
    const uint8_t our_sk[56], const uint8_t their_pk[56])
    { (void)ss; (void)our_sk; (void)their_pk; return -1; }

#endif /* NEXTSSL_BUILD_LITE */

/* =========================================================================
 * ML-KEM-768
 *
 * Root argument order:
 *   encaps: (pk, ct, ss)    base: (ct, ss, pk)
 *   decaps: (ct, sk, ss)    base: (ss, ct, sk)
 * ====================================================================== */

int nextssl_base_dhcm_ml_kem_768_keypair(uint8_t *public_key,
                                          uint8_t *secret_key)
{
    if (!public_key || !secret_key) return -1;
    return nextssl_root_pqc_kem_mlkem768_keygen(public_key, secret_key);
}

int nextssl_base_dhcm_ml_kem_768_encapsulate(uint8_t *ciphertext,
                                              uint8_t *shared_secret,
                                              const uint8_t *public_key)
{
    if (!ciphertext || !shared_secret || !public_key) return -1;
    return nextssl_root_pqc_kem_mlkem768_encaps(public_key, ciphertext,
                                                 shared_secret);
}

int nextssl_base_dhcm_ml_kem_768_decapsulate(uint8_t *shared_secret,
                                              const uint8_t *ciphertext,
                                              const uint8_t *secret_key)
{
    if (!shared_secret || !ciphertext || !secret_key) return -1;
    return nextssl_root_pqc_kem_mlkem768_decaps(ciphertext, secret_key,
                                                 shared_secret);
}

/* =========================================================================
 * ECDH P-256
 * No root-layer P-256 implementation exists yet.
 * TODO: add nextssl_root_ecc_p256_* functions in root_ecc.c/h.
 * ====================================================================== */

int nextssl_base_dhcm_p256_keypair(uint8_t public_key[64],
                                    uint8_t secret_key[32])
{
    (void)public_key; (void)secret_key;
    return -1;
}

int nextssl_base_dhcm_p256_exchange(uint8_t shared_secret[32],
                                     const uint8_t our_secret_key[32],
                                     const uint8_t their_public_key[64])
{
    (void)shared_secret; (void)our_secret_key; (void)their_public_key;
    return -1;
}

/* =========================================================================
 * Self-test (no-op — unit tests live in test/)
 * ====================================================================== */

int nextssl_base_dhcm_selftest(void)
{
    return 0;
}
