/**
 * @file core/pqc/sign.c
 * @brief Layer 2 (base) sign shim — delegates to root layer.
 *
 * Naming note: these functions are prefixed nextssl_base_* per the
 * NEXTSSL_BASE_API convention in visibility.h; the directory is
 * interfaces/core/. The prefix and directory name are inconsistent
 * (pre-existing: "base" API macro vs "core" directory). No rename
 * is done here — callers in main/full/ already use nextssl_base_*.
 *
 * Delegation map:
 *   nextssl_base_sign_ed25519_*   → nextssl_root_ecc_ed25519_* (root_ecc.h)
 *   nextssl_base_sign_ml_dsa_65_* → nextssl_root_pqc_sign_mldsa65_* (root_pqc_sign.h)
 *                                   (full build only; lite returns -1)
 *   nextssl_base_sign_ecdsa_p256_* → stub -1 (no root P-256 layer yet)
 */

#include "sign.h"
#include "../../root/core/root_ecc.h"
#include "../../root/pqc/root_pqc_sign.h"

/* =========================================================================
 * Ed25519
 * ====================================================================== */

int nextssl_base_sign_ed25519_keypair(uint8_t public_key[32],
                                      uint8_t secret_key[64])
{
    if (!public_key || !secret_key) return -1;
    return nextssl_root_ecc_ed25519_keygen(public_key, secret_key);
}

int nextssl_base_sign_ed25519_sign(uint8_t signature[64],
                                   const uint8_t *message, size_t message_len,
                                   const uint8_t secret_key[64])
{
    if (!signature || !message || !secret_key) return -1;
    return nextssl_root_ecc_ed25519_sign(signature, message, message_len,
                                         secret_key);
}

int nextssl_base_sign_ed25519_verify(const uint8_t signature[64],
                                     const uint8_t *message, size_t message_len,
                                     const uint8_t public_key[32])
{
    if (!signature || !message || !public_key) return -1;
    /* root returns 1 if valid, 0 if invalid — same convention as base */
    return nextssl_root_ecc_ed25519_verify(signature, message, message_len,
                                            public_key);
}

/* =========================================================================
 * ECDSA P-256
 * No root-layer P-256 implementation exists yet. These stubs return -1
 * so that callers get a clear error instead of a link failure.
 * TODO: add nextssl_root_ecc_p256_* functions in root_ecc.c/h.
 * ====================================================================== */

int nextssl_base_sign_ecdsa_p256_keypair(uint8_t public_key[64],
                                          uint8_t secret_key[32])
{
    (void)public_key; (void)secret_key;
    return -1;
}

int nextssl_base_sign_ecdsa_p256_sign(uint8_t signature[64],
                                       const uint8_t *message, size_t message_len,
                                       const uint8_t secret_key[32])
{
    (void)signature; (void)message; (void)message_len; (void)secret_key;
    return -1;
}

int nextssl_base_sign_ecdsa_p256_verify(const uint8_t signature[64],
                                         const uint8_t *message, size_t message_len,
                                         const uint8_t public_key[64])
{
    (void)signature; (void)message; (void)message_len; (void)public_key;
    return -1;
}

/* =========================================================================
 * ML-DSA-65 (post-quantum)
 * Only available in the full build; the root layer guards mldsa65 with
 * #ifndef NEXTSSL_BUILD_LITE. Return -1 in lite to keep link clean.
 * ====================================================================== */

#ifndef NEXTSSL_BUILD_LITE

int nextssl_base_sign_ml_dsa_65_keypair(uint8_t *public_key,
                                         uint8_t *secret_key)
{
    if (!public_key || !secret_key) return -1;
    return nextssl_root_pqc_sign_mldsa65_keygen(public_key, secret_key);
}

int nextssl_base_sign_ml_dsa_65_sign(uint8_t *signature,
                                      size_t *signature_len,
                                      const uint8_t *message, size_t message_len,
                                      const uint8_t *secret_key)
{
    if (!signature || !signature_len || !message || !secret_key) return -1;
    return nextssl_root_pqc_sign_mldsa65_sign(signature, signature_len,
                                               message, message_len, secret_key);
}

int nextssl_base_sign_ml_dsa_65_verify(const uint8_t *signature,
                                        size_t signature_len,
                                        const uint8_t *message, size_t message_len,
                                        const uint8_t *public_key)
{
    if (!signature || !message || !public_key) return -1;
    /* root returns 1 if valid, 0 if invalid — same convention as base */
    return nextssl_root_pqc_sign_mldsa65_verify(signature, signature_len,
                                                 message, message_len, public_key);
}

#else  /* NEXTSSL_BUILD_LITE */

int nextssl_base_sign_ml_dsa_65_keypair(uint8_t *pk, uint8_t *sk)
    { (void)pk; (void)sk; return -1; }
int nextssl_base_sign_ml_dsa_65_sign(uint8_t *sig, size_t *sig_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *sk)
    { (void)sig;(void)sig_len;(void)msg;(void)msg_len;(void)sk; return -1; }
int nextssl_base_sign_ml_dsa_65_verify(const uint8_t *sig, size_t sig_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *pk)
    { (void)sig;(void)sig_len;(void)msg;(void)msg_len;(void)pk; return -1; }

#endif /* NEXTSSL_BUILD_LITE */

/* =========================================================================
 * Self-test (no-op — unit tests live in test/)
 * ====================================================================== */

int nextssl_base_sign_selftest(void)
{
    return 0;
}
