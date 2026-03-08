/**
 * @file sign.c
 * @brief Layer 3: Signature dispatcher (full build)
 * @layer main
 * @category sign
 */

#include "sign.h"
#include "../../core/pqc/sign.h"

/* ========== Ed25519 ========== */

NEXTSSL_MAIN_API int nextssl_sign_keypair(
    uint8_t public_key[32],
    uint8_t secret_key[64])
{
    if (!public_key || !secret_key) return -1;
    return nextssl_base_sign_ed25519_keypair(public_key, secret_key);
}

NEXTSSL_MAIN_API int nextssl_sign(
    uint8_t signature[64],
    const uint8_t *message, size_t message_len,
    const uint8_t secret_key[64])
{
    if (!signature || !message || !secret_key) return -1;
    return nextssl_base_sign_ed25519_sign(signature, message, message_len, secret_key);
}

NEXTSSL_MAIN_API int nextssl_verify(
    const uint8_t signature[64],
    const uint8_t *message, size_t message_len,
    const uint8_t public_key[32])
{
    if (!signature || !message || !public_key) return -1;
    return nextssl_base_sign_ed25519_verify(signature, message, message_len, public_key);
}

/* ========== ML-DSA-65 (post-quantum) ========== */

NEXTSSL_MAIN_API int nextssl_pq_sign_keypair(
    uint8_t *public_key,
    uint8_t *secret_key)
{
    if (!public_key || !secret_key) return -1;
    return nextssl_base_sign_ml_dsa_65_keypair(public_key, secret_key);
}

NEXTSSL_MAIN_API int nextssl_pq_sign(
    uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key)
{
    if (!signature || !signature_len || !message || !secret_key) return -1;
    return nextssl_base_sign_ml_dsa_65_sign(signature, signature_len,
                                            message, message_len, secret_key);
}

NEXTSSL_MAIN_API int nextssl_pq_verify(
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *public_key)
{
    if (!signature || !message || !public_key) return -1;
    return nextssl_base_sign_ml_dsa_65_verify(signature, signature_len,
                                              message, message_len, public_key);
}
