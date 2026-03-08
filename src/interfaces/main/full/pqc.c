/**
 * @file pqc.c
 * @brief Layer 3: Post-quantum cryptography dispatcher (full build)
 * @layer main
 * @category pqc
 */

#include "pqc.h"
#include "../../core/dhcm/dhcm.h"
#include "../../core/pqc/sign.h"

/* ========== ML-KEM-768 ========== */

NEXTSSL_MAIN_API int nextssl_pqc_kem_keypair(
    uint8_t *public_key,
    uint8_t *secret_key)
{
    if (!public_key || !secret_key) return -1;
    return nextssl_base_dhcm_ml_kem_768_keypair(public_key, secret_key);
}

NEXTSSL_MAIN_API int nextssl_pqc_kem_encapsulate(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key)
{
    if (!ciphertext || !shared_secret || !public_key) return -1;
    return nextssl_base_dhcm_ml_kem_768_encapsulate(ciphertext, shared_secret, public_key);
}

NEXTSSL_MAIN_API int nextssl_pqc_kem_decapsulate(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key)
{
    if (!shared_secret || !ciphertext || !secret_key) return -1;
    return nextssl_base_dhcm_ml_kem_768_decapsulate(shared_secret, ciphertext, secret_key);
}

/* ========== ML-DSA-65 ========== */

NEXTSSL_MAIN_API int nextssl_pqc_sign_keypair(
    uint8_t *public_key,
    uint8_t *secret_key)
{
    if (!public_key || !secret_key) return -1;
    return nextssl_base_sign_ml_dsa_65_keypair(public_key, secret_key);
}

NEXTSSL_MAIN_API int nextssl_pqc_sign(
    uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key)
{
    if (!signature || !signature_len || !message || !secret_key) return -1;
    return nextssl_base_sign_ml_dsa_65_sign(signature, signature_len,
                                            message, message_len, secret_key);
}

NEXTSSL_MAIN_API int nextssl_pqc_verify(
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *public_key)
{
    if (!signature || !message || !public_key) return -1;
    return nextssl_base_sign_ml_dsa_65_verify(signature, signature_len,
                                              message, message_len, public_key);
}
