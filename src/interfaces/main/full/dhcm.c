/**
 * @file dhcm.c
 * @brief Layer 3: Key-exchange dispatcher (full build)
 * @layer main
 * @category dhcm
 */

#include "dhcm.h"
#include "../../core/dhcm/dhcm.h"

/* ========== X25519 ========== */

NEXTSSL_MAIN_API int nextssl_keyexchange_keypair(
    uint8_t public_key[32],
    uint8_t secret_key[32])
{
    if (!public_key || !secret_key) return -1;
    return nextssl_base_dhcm_x25519_keypair(public_key, secret_key);
}

NEXTSSL_MAIN_API int nextssl_keyexchange_compute(
    uint8_t shared_secret[32],
    const uint8_t our_secret_key[32],
    const uint8_t their_public_key[32])
{
    if (!shared_secret || !our_secret_key || !their_public_key) return -1;
    return nextssl_base_dhcm_x25519_exchange(shared_secret, our_secret_key, their_public_key);
}

/* ========== ML-KEM-768 (post-quantum) ========== */

NEXTSSL_MAIN_API int nextssl_pq_keyexchange_keypair(
    uint8_t *public_key,
    uint8_t *secret_key)
{
    if (!public_key || !secret_key) return -1;
    return nextssl_base_dhcm_ml_kem_768_keypair(public_key, secret_key);
}

NEXTSSL_MAIN_API int nextssl_pq_keyexchange_encapsulate(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *their_public_key)
{
    if (!ciphertext || !shared_secret || !their_public_key) return -1;
    return nextssl_base_dhcm_ml_kem_768_encapsulate(ciphertext, shared_secret, their_public_key);
}

NEXTSSL_MAIN_API int nextssl_pq_keyexchange_decapsulate(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *our_secret_key)
{
    if (!shared_secret || !ciphertext || !our_secret_key) return -1;
    return nextssl_base_dhcm_ml_kem_768_decapsulate(shared_secret, ciphertext, our_secret_key);
}
