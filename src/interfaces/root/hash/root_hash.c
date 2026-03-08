/**
 * @file root/hash/root_hash.c
 * @brief NextSSL Root — Hash implementation (all algorithms).
 */

#include "root_hash.h"
#include "../root_internal.h"

/* SHA-2 */
#ifndef NEXTSSL_BUILD_LITE
#include "../../../primitives/hash/fast/sha224/sha224.h"
#endif
#include "../../../primitives/hash/fast/sha256/sha256.h"
#include "../../../primitives/hash/fast/sha512/sha512.h"

/* BLAKE2 / BLAKE3 */
#ifndef NEXTSSL_BUILD_LITE
#include "../../../primitives/hash/fast/blake2b/blake2b.h"
#include "../../../primitives/hash/fast/blake2s/blake2s.h"
#endif
#include "../../../primitives/hash/fast/blake3/blake3.h"

/* SHA-3 / Keccak / SHAKE */
#ifndef NEXTSSL_BUILD_LITE
#include "../../../primitives/hash/sponge_xof/sha3_224/sha3_224.h"
#include "../../../primitives/hash/sponge_xof/sha3/sha3.h"
#include "../../../primitives/hash/sponge_xof/sha3_384/sha3_384.h"
#include "../../../primitives/hash/sponge_xof/keccak/keccak.h"
#include "../../../primitives/hash/sponge_xof/shake/shake.h"
#endif

/* Argon2 */
#include "../../../primitives/hash/memory_hard/Argon2id/argon2id.h"
#ifndef NEXTSSL_BUILD_LITE
#include "../../../primitives/hash/memory_hard/Argon2d/argon2d.h"
#include "../../../primitives/hash/memory_hard/Argon2i/argon2i.h"
#endif

/* =========================================================================
 * SHA-2
 * ====================================================================== */

#ifndef NEXTSSL_BUILD_LITE
NEXTSSL_API int nextssl_root_hash_sha224(const uint8_t *data, size_t len,
                                          uint8_t out[28]) {
    if (!data || !out) return -1;
    sha224_hash(data, len, out);
    return 0;
}
#endif /* NEXTSSL_BUILD_LITE */

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

/* =========================================================================
 * BLAKE2 / BLAKE3
 * ====================================================================== */

#ifndef NEXTSSL_BUILD_LITE
NEXTSSL_API int nextssl_root_hash_blake2b(const uint8_t *data, size_t len,
                                           uint8_t *out, size_t out_len) {
    if (!data || !out || out_len == 0 || out_len > 64) return -1;
    BLAKE2B_CTX ctx;
    if (blake2b_init(&ctx, out_len) != 0) return -1;
    if (blake2b_update(&ctx, data, len) != 0) return -1;
    return blake2b_final(&ctx, out, out_len) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_hash_blake2s(const uint8_t *data, size_t len,
                                           uint8_t *out, size_t out_len) {
    if (!data || !out || out_len == 0 || out_len > 32) return -1;
    BLAKE2S_CTX ctx;
    if (blake2s_init(&ctx, out_len) != 0) return -1;
    if (blake2s_update(&ctx, data, len) != 0) return -1;
    return blake2s_final(&ctx, out, out_len) == 0 ? 0 : -1;
}
#endif /* NEXTSSL_BUILD_LITE */

NEXTSSL_API int nextssl_root_hash_blake3(const uint8_t *data, size_t len,
                                          uint8_t *out, size_t out_len) {
    if (!data || !out || out_len == 0) return -1;
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, data, len);
    blake3_hasher_finalize(&h, out, out_len);
    return 0;
}

/* =========================================================================
 * SHA-3 / Keccak
 * ====================================================================== */

#ifndef NEXTSSL_BUILD_LITE

NEXTSSL_API int nextssl_root_hash_sha3_224(const uint8_t *data, size_t len,
                                            uint8_t out[28]) {
    if (!data || !out) return -1;
    sha3_224_hash(data, len, out);
    return 0;
}

NEXTSSL_API int nextssl_root_hash_sha3_256(const uint8_t *data, size_t len,
                                            uint8_t out[32]) {
    if (!data || !out) return -1;
    sha3_256_hash(data, len, out);
    return 0;
}

NEXTSSL_API int nextssl_root_hash_sha3_384(const uint8_t *data, size_t len,
                                            uint8_t out[48]) {
    if (!data || !out) return -1;
    sha3_384_hash(data, len, out);
    return 0;
}

NEXTSSL_API int nextssl_root_hash_sha3_512(const uint8_t *data, size_t len,
                                            uint8_t out[64]) {
    if (!data || !out) return -1;
    sha3_512_hash(data, len, out);
    return 0;
}

NEXTSSL_API int nextssl_root_hash_keccak256(const uint8_t *data, size_t len,
                                             uint8_t out[32]) {
    if (!data || !out) return -1;
    keccak_256_hash(data, len, out);
    return 0;
}

/* =========================================================================
 * SHAKE (XOF)
 * ====================================================================== */

NEXTSSL_API int nextssl_root_hash_shake128(const uint8_t *data, size_t len,
                                            uint8_t *out, size_t out_len) {
    if (!data || !out || out_len == 0) return -1;
    shake128_hash(data, len, out, out_len);
    return 0;
}

NEXTSSL_API int nextssl_root_hash_shake256(const uint8_t *data, size_t len,
                                            uint8_t *out, size_t out_len) {
    if (!data || !out || out_len == 0) return -1;
    shake256_hash(data, len, out, out_len);
    return 0;
}
#endif /* NEXTSSL_BUILD_LITE */

/* =========================================================================
 * Argon2
 * ====================================================================== */

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

#ifndef NEXTSSL_BUILD_LITE
NEXTSSL_API int nextssl_root_hash_argon2d(const uint8_t *pw, size_t pw_len,
                                           const uint8_t *salt, size_t salt_len,
                                           uint32_t t_cost, uint32_t m_cost,
                                           uint32_t par,
                                           uint8_t *out, size_t out_len) {
    if (!pw || !salt || !out || out_len == 0) return -1;
    return argon2d_hash_raw(t_cost, m_cost, par,
                             pw, pw_len, salt, salt_len,
                             out, out_len) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_hash_argon2i(const uint8_t *pw, size_t pw_len,
                                           const uint8_t *salt, size_t salt_len,
                                           uint32_t t_cost, uint32_t m_cost,
                                           uint32_t par,
                                           uint8_t *out, size_t out_len) {
    if (!pw || !salt || !out || out_len == 0) return -1;
    return argon2i_hash_raw(t_cost, m_cost, par,
                             pw, pw_len, salt, salt_len,
                             out, out_len) == 0 ? 0 : -1;
}
#endif /* NEXTSSL_BUILD_LITE */
