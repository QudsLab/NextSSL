/**
 * @file nextssl.c
 * @brief Full variant primary interface (Layer 4) — lifecycle only
 *
 * Crypto implementations live in Layer 3 (src/interfaces/main/full/).
 * This file provides only: version/variant metadata, profile init,
 * config-based lifecycle, selftest coordination, and thin name-wrappers
 * for the few symbols whose names diverge between Layer 3 and Layer 4.
 */

#ifndef NEXTSSL_BUILDING_DLL
#  define NEXTSSL_BUILDING_DLL
#endif

#include "nextssl.h"
/* Layer 3 dispatch headers */
#include "hash.h"
#include "aead.h"
#include "sign.h"
#include "dhcm.h"
#include "pqc.h"
#include "pow.h"
#include "core.h"
/* Config system */
#include "../../../config/config.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* ========================================================================== */
/*  Version / Variant                                                          */
/* ========================================================================== */

NEXTSSL_API const char* nextssl_version(void) {
    return "NextSSL v0.0.1-beta";
}

NEXTSSL_API const char* nextssl_variant(void) {
    return "full";
}

NEXTSSL_API const char* nextssl_security_level(void) {
    return nextssl_config_security_level();
}

/* ========================================================================== */
/*  Name-compatibility wrappers                                                */
/*                                                                             */
/*  primary/full/nextssl.h exposes nextssl_pq_kem_* while Layer 3 uses        */
/*  nextssl_pqc_kem_*.  Thin wrappers bridge the gap.                         */
/* ========================================================================== */

NEXTSSL_API int nextssl_pq_kem_keypair(
    uint8_t *public_key,
    uint8_t *secret_key)
{
    return nextssl_pqc_kem_keypair(public_key, secret_key);
}

NEXTSSL_API int nextssl_pq_kem_encapsulate(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key)
{
    return nextssl_pqc_kem_encapsulate(ciphertext, shared_secret, public_key);
}

NEXTSSL_API int nextssl_pq_kem_decapsulate(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key)
{
    return nextssl_pqc_kem_decapsulate(shared_secret, ciphertext, secret_key);
}

/* ========================================================================== */
/*  Initialization & Self-Test                                                 */
/* ========================================================================== */

NEXTSSL_API int nextssl_init(int profile) {
    if ((unsigned)profile >= (unsigned)NEXTSSL_PROFILE_MAX) {
        profile = NEXTSSL_PROFILE_MODERN;
    }
    const nextssl_config_t *cfg =
        nextssl_config_init((nextssl_profile_t)profile);
    return (cfg != NULL || nextssl_config_get() != NULL) ? 0 : -1;
}

NEXTSSL_API int nextssl_init_custom(const nextssl_custom_profile_t *profile) {
    if (profile == NULL) return -1;
    nextssl_profile_custom_t internal;
    internal.hash  = (nextssl_hash_algo_t)profile->hash;
    internal.aead  = (nextssl_aead_algo_t)profile->aead;
    internal.kdf   = (nextssl_kdf_algo_t)profile->kdf;
    internal.sign  = (nextssl_sign_algo_t)profile->sign;
    internal.kem   = (nextssl_kem_algo_t)profile->kem;
    internal.pow   = (nextssl_pow_algo_t)profile->pow;
    internal.name  = profile->name;
    const nextssl_config_t *cfg = nextssl_config_init_custom(&internal);
    if (cfg == NULL) {
        return (nextssl_config_get() != NULL) ? -2 : -3;
    }
    return 0;
}

NEXTSSL_API int nextssl_selftest(void) {
    /* Hash round-trip */
    uint8_t hash[32];
    const uint8_t msg[] = "abc";
    if (nextssl_hash(msg, 3, hash) != 0) return -1;

    /* Encrypt/decrypt round-trip */
    uint8_t key[32] = {0};
    uint8_t pt[16]  = "selftest payload";
    uint8_t ct[44], rt[16];
    size_t ct_len, rt_len;
    if (nextssl_encrypt(key, pt, 16, ct, &ct_len) != 0) return -2;
    if (nextssl_decrypt(key, ct, ct_len, rt, &rt_len) != 0) return -3;
    if (rt_len != 16 || memcmp(pt, rt, 16) != 0) return -3;

    /* X25519 key exchange round-trip */
    uint8_t pk_a[32], sk_a[32], pk_b[32], sk_b[32], ss_a[32], ss_b[32];
    if (nextssl_keyexchange_keypair(pk_a, sk_a) != 0) return -4;
    if (nextssl_keyexchange_keypair(pk_b, sk_b) != 0) return -4;
    if (nextssl_keyexchange_compute(ss_a, sk_a, pk_b) != 0) return -4;
    if (nextssl_keyexchange_compute(ss_b, sk_b, pk_a) != 0) return -4;
    if (!nextssl_constant_compare(ss_a, ss_b, 32)) return -4;

    /* Ed25519 sign/verify round-trip */
    uint8_t epk[32], esk[64], sig[64];
    if (nextssl_sign_keypair(epk, esk) != 0) return -5;
    if (nextssl_sign(sig, msg, 3, esk) != 0) return -5;
    if (nextssl_verify(sig, msg, 3, epk) != 1) return -5;

    return 0;
}

NEXTSSL_API void nextssl_cleanup(void) {
    nextssl_config_reset();
}
