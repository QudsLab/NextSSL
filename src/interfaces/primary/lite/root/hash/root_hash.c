/**
 * @file root/hash/root_hash.c (Lite)
 * @brief NextSSL Root Lite -- Hash implementations.
 */

#ifndef NEXTSSL_BUILDING_DLL
#define NEXTSSL_BUILDING_DLL
#endif

#include "root_hash.h"
#include "../../../../../primitives/hash/fast/sha256/sha256.h"
#include "../../../../../primitives/hash/fast/sha512/sha512.h"
#include "../../../../../primitives/hash/fast/blake3/blake3.h"
#include "../../../../../primitives/hash/memory_hard/Argon2id/argon2id.h"

NEXTSSL_API int nextssl_root_hash_sha256(const uint8_t *data, size_t len,
                                          uint8_t out[32]) {
    if (!data || !out) return -1;
    sha256(data, len, out);
    return 0;
}

NEXTSSL_API int nextssl_root_hash_sha512(const uint8_t *data, size_t len,
                                          uint8_t out[64]) {
    if (!data || !out) return -1;
    sha512_hash(data, len, out);
    return 0;
}

NEXTSSL_API int nextssl_root_hash_blake3(const uint8_t *data, size_t len,
                                          uint8_t *out, size_t out_len) {
    if (!data || !out || out_len == 0) return -1;
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, data, len);
    blake3_hasher_finalize(&h, out, out_len);
    return 0;
}

NEXTSSL_API int nextssl_root_hash_argon2id(const uint8_t *pw, size_t pw_len,
                                            const uint8_t *salt, size_t salt_len,
                                            uint32_t t_cost, uint32_t m_cost,
                                            uint32_t par,
                                            uint8_t *out, size_t out_len) {
    if (!pw || !salt || !out || out_len == 0) return -1;
    return argon2id_hash_raw(t_cost, m_cost, par,
                             pw, pw_len, salt, salt_len,
                             out, out_len) == 0 ? 0 : -1;
}
