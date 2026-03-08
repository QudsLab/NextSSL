/**
 * @file pow.c
 * @brief Layer 2: Argon2id password-hashing wrappers (nextssl_base_pow_*)
 * @layer core/base
 *
 * Thin wrappers around the Argon2id primitive providing encoded-hash
 * (PHC string format) operations for the Layer 3 (main) dispatch layer.
 */

#ifndef NEXTSSL_BUILDING_DLL
#define NEXTSSL_BUILDING_DLL
#endif

#include "pow.h"
#include "../../../primitives/hash/memory_hard/utils/argon2.h"
#include "../../../seed/rng/rng.h"

/* OWASP 2023 recommended defaults */
#define BASE_ARGON2ID_T_COST    4
#define BASE_ARGON2ID_M_COST    (256 * 1024)   /* 256 MiB */
#define BASE_ARGON2ID_PARALLEL  4
#define BASE_ARGON2ID_SALTLEN   16
#define BASE_ARGON2ID_HASHLEN   32

int nextssl_base_pow_argon2id_hash(
    const uint8_t *password, size_t password_len,
    char *hash_out, size_t hash_out_len)
{
    if (!password || !hash_out) return -1;
    uint8_t salt[BASE_ARGON2ID_SALTLEN];
    if (rng_fill(salt, sizeof(salt)) != 0) return -1;
    int ret = argon2id_hash_encoded(
        BASE_ARGON2ID_T_COST, BASE_ARGON2ID_M_COST, BASE_ARGON2ID_PARALLEL,
        password, password_len,
        salt, sizeof(salt),
        BASE_ARGON2ID_HASHLEN,
        hash_out, hash_out_len);
    return (ret == ARGON2_OK) ? 0 : -1;
}

int nextssl_base_pow_argon2id_hash_custom(
    const uint8_t *password, size_t password_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    char *hash_out, size_t hash_out_len)
{
    if (!password || !hash_out) return -1;
    if (t_cost < 1 || m_cost < 8 || parallelism < 1) return -1;
    uint8_t salt[BASE_ARGON2ID_SALTLEN];
    if (rng_fill(salt, sizeof(salt)) != 0) return -1;
    int ret = argon2id_hash_encoded(
        t_cost, m_cost, parallelism,
        password, password_len,
        salt, sizeof(salt),
        BASE_ARGON2ID_HASHLEN,
        hash_out, hash_out_len);
    return (ret == ARGON2_OK) ? 0 : -1;
}

int nextssl_base_pow_argon2id_verify(
    const uint8_t *password, size_t password_len,
    const char *hash_encoded)
{
    if (!password || !hash_encoded) return -1;
    int ret = argon2id_verify(hash_encoded, password, password_len);
    if (ret == ARGON2_OK) return 1;
    if (ret == ARGON2_VERIFY_MISMATCH) return 0;
    return -1;
}
