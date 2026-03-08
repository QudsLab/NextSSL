/**
 * @file pow.c
 * @brief Layer 3: Password-hashing dispatcher (full build)
 * @layer main
 * @category pow
 *
 * Delegates to Layer 2 Argon2id password-hashing wrappers which handle
 * random-salt generation, PHC-string encoding, and constant-time verify.
 *
 * Strength mapping for nextssl_password_hash_custom():
 *   1 = low   : t=2, m=64MB   (testing / low-resource)
 *   2 = medium: t=3, m=128MB  (legacy systems)
 *   3 = high  : t=5, m=512MB  (high-security)
 */

#include "pow.h"
#include "../../core/pow/pow.h"

NEXTSSL_MAIN_API int nextssl_password_hash(
    const char *password, size_t password_len,
    char *hash_output, size_t hash_output_len)
{
    if (!password || !hash_output) return -1;
    return nextssl_base_pow_argon2id_hash(
        (const uint8_t *)password, password_len,
        hash_output, hash_output_len);
}

NEXTSSL_MAIN_API int nextssl_password_verify(
    const char *password, size_t password_len,
    const char *stored_hash)
{
    if (!password || !stored_hash) return -1;
    return nextssl_base_pow_argon2id_verify(
        (const uint8_t *)password, password_len,
        stored_hash);
}

NEXTSSL_MAIN_API int nextssl_password_hash_custom(
    const char *password, size_t password_len,
    int strength,
    char *hash_output, size_t hash_output_len)
{
    if (!password || !hash_output) return -1;

    uint32_t t_cost, m_cost;
    switch (strength) {
        case 1:  t_cost = 2; m_cost =  65536; break;  /* 64 MB  */
        case 2:  t_cost = 3; m_cost = 131072; break;  /* 128 MB */
        case 3:  t_cost = 5; m_cost = 524288; break;  /* 512 MB */
        default: return -1;
    }

    return nextssl_base_pow_argon2id_hash_custom(
        (const uint8_t *)password, password_len,
        t_cost, m_cost, 4,
        hash_output, hash_output_len);
}
