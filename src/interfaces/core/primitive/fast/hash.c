/**
 * @file hash.c
 * @brief Layer 2: Hash primitive wrappers (nextssl_base_hash_*)
 * @layer core/base
 *
 * Thin wrappers around Layer 1 hash primitives providing validated,
 * uniform interfaces for the Layer 3 (main) dispatch layer.
 */

#ifndef NEXTSSL_BUILDING_DLL
#define NEXTSSL_BUILDING_DLL
#endif

#include "hash.h"
#include "../../../primitives/hash/fast/sha256/sha256.h"
#include "../../../primitives/hash/fast/sha512/sha512.h"
#include "../../../primitives/hash/sponge_xof/sha3/sha3.h"
#include "../../../primitives/hash/fast/blake2b/blake2b.h"
#include "../../../primitives/hash/fast/blake3/blake3.h"

int nextssl_base_hash_sha256(const uint8_t *data, size_t len, uint8_t hash[32])
{
    if (!data || !hash) return -1;
    sha256(data, len, hash);
    return 0;
}

int nextssl_base_hash_sha512(const uint8_t *data, size_t len, uint8_t hash[64])
{
    if (!data || !hash) return -1;
    sha512_hash(data, len, hash);
    return 0;
}

int nextssl_base_hash_sha3_256(const uint8_t *data, size_t len, uint8_t hash[32])
{
    if (!data || !hash) return -1;
    sha3_256_hash(data, len, hash);
    return 0;
}

int nextssl_base_hash_sha3_512(const uint8_t *data, size_t len, uint8_t hash[64])
{
    if (!data || !hash) return -1;
    sha3_512_hash(data, len, hash);
    return 0;
}

int nextssl_base_hash_blake2b(const uint8_t *data, size_t len,
                               uint8_t *hash, size_t hash_len)
{
    if (!data || !hash || hash_len == 0 || hash_len > 64) return -1;
    BLAKE2B_CTX ctx;
    if (blake2b_init(&ctx, hash_len) != 0) return -1;
    if (blake2b_update(&ctx, data, len) != 0) return -1;
    return blake2b_final(&ctx, hash, hash_len) == 0 ? 0 : -1;
}

int nextssl_base_hash_blake3(const uint8_t *data, size_t len, uint8_t hash[32])
{
    if (!data || !hash) return -1;
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, data, len);
    blake3_hasher_finalize(&h, hash, 32);
    return 0;
}

int nextssl_base_hash_selftest(void)
{
    return 0;
}
