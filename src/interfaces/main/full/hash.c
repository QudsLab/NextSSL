/**
 * @file hash.c
 * @brief Layer 3: Hash dispatcher (full build)
 * @layer main
 * @category hash
 */

#include "hash.h"
#include "../../core/primitive/fast/hash.h"

NEXTSSL_MAIN_API int nextssl_hash(
    const uint8_t *data, size_t data_len,
    uint8_t hash[32])
{
    if (!data || !hash) return -1;
    return nextssl_base_hash_sha256(data, data_len, hash);
}

NEXTSSL_MAIN_API int nextssl_hash_512(
    const uint8_t *data, size_t data_len,
    uint8_t hash[64])
{
    if (!data || !hash) return -1;
    return nextssl_base_hash_sha512(data, data_len, hash);
}

NEXTSSL_MAIN_API int nextssl_hash_sha3(
    const uint8_t *data, size_t data_len,
    uint8_t hash[32])
{
    if (!data || !hash) return -1;
    return nextssl_base_hash_sha3_256(data, data_len, hash);
}

NEXTSSL_MAIN_API int nextssl_hash_fast(
    const uint8_t *data, size_t data_len,
    uint8_t hash[32])
{
    if (!data || !hash) return -1;
    return nextssl_base_hash_blake3(data, data_len, hash);
}
