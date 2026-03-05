/**
 * @file root/legacy/root_legacy.c
 * @brief NextSSL Root — Legacy algorithm implementation.
 */

#include "root_legacy.h"
#include "../root_internal.h"

/* Alive */
#include "../../../../../legacy/alive/sha1/sha1.h"
#include "../../../../../legacy/alive/md5/md5.h"
#include "../../../../../legacy/alive/ripemd160/ripemd160.h"
#include "../../../../../legacy/alive/whirlpool/whirlpool.h"
#include "../../../../../legacy/alive/nt_hash/nt.h"
#include "../../../../../legacy/alive/aes_ecb/aes_ecb.h"

/* Unsafe */
#include "../../../../../legacy/unsafe/sha0/sha0.h"
#include "../../../../../legacy/unsafe/md2/md2.h"
#include "../../../../../legacy/unsafe/md4/md4.h"
#include "../../../../../legacy/unsafe/has160/has160.h"
#include "../../../../../legacy/unsafe/ripemd128/ripemd128.h"
#include "../../../../../legacy/unsafe/ripemd256/ripemd256.h"
#include "../../../../../legacy/unsafe/ripemd320/ripemd320.h"

/* =========================================================================
 * ALIVE
 * ====================================================================== */

NEXTSSL_API int nextssl_root_legacy_alive_sha1(const uint8_t *data, size_t len,
                                                uint8_t out[20]) {
    if (!data || !out) return -1;
    sha1_hash(data, len, out);
    return 0;
}

NEXTSSL_API int nextssl_root_legacy_alive_md5(const uint8_t *data, size_t len,
                                               uint8_t out[16]) {
    if (!data || !out) return -1;
    md5_hash(data, len, out);
    return 0;
}

NEXTSSL_API int nextssl_root_legacy_alive_ripemd160(const uint8_t *data, size_t len,
                                                     uint8_t out[20]) {
    if (!data || !out) return -1;
    ripemd160_hash(data, len, out);
    return 0;
}

NEXTSSL_API int nextssl_root_legacy_alive_whirlpool(const uint8_t *data, size_t len,
                                                     uint8_t out[64]) {
    if (!data || !out) return -1;
    whirlpool_hash(data, len, out);
    return 0;
}

NEXTSSL_API int nextssl_root_legacy_alive_nthash(const char *password,
                                                  uint8_t out[16]) {
    if (!password || !out) return -1;
    nt_hash(password, out);
    return 0;
}

NEXTSSL_API int nextssl_root_legacy_alive_aesecb_encrypt(const uint8_t *key, size_t key_len,
                                                          const uint8_t *pt, size_t pt_len,
                                                          uint8_t *ct) {
    if (!key || !pt || !ct) return -1;
    if (key_len != 16 && key_len != 24 && key_len != 32) return -1;
    if (pt_len == 0 || pt_len % 16 != 0) return -1;
    AES_ECB_encrypt(key, pt, pt_len, ct);
    return 0;
}

NEXTSSL_API int nextssl_root_legacy_alive_aesecb_decrypt(const uint8_t *key, size_t key_len,
                                                          const uint8_t *ct, size_t ct_len,
                                                          uint8_t *pt) {
    if (!key || !ct || !pt) return -1;
    if (key_len != 16 && key_len != 24 && key_len != 32) return -1;
    if (ct_len == 0 || ct_len % 16 != 0) return -1;
    return AES_ECB_decrypt(key, ct, ct_len, pt) == 0 ? 0 : -1;
}

/* =========================================================================
 * UNSAFE
 * ====================================================================== */

NEXTSSL_API int nextssl_root_legacy_unsafe_sha0(const uint8_t *data, size_t len,
                                                 uint8_t out[20]) {
    if (!data || !out) return -1;
    sha0_hash(data, len, out);
    return 0;
}

NEXTSSL_API int nextssl_root_legacy_unsafe_md2(const uint8_t *data, size_t len,
                                                uint8_t out[16]) {
    if (!data || !out) return -1;
    md2_hash(data, len, out);
    return 0;
}

NEXTSSL_API int nextssl_root_legacy_unsafe_md4(const uint8_t *data, size_t len,
                                                uint8_t out[16]) {
    if (!data || !out) return -1;
    md4_hash(data, len, out);
    return 0;
}

NEXTSSL_API int nextssl_root_legacy_unsafe_has160(const uint8_t *data, size_t len,
                                                   uint8_t out[20]) {
    if (!data || !out) return -1;
    has160_hash(data, len, out);
    return 0;
}

NEXTSSL_API int nextssl_root_legacy_unsafe_ripemd128(const uint8_t *data, size_t len,
                                                      uint8_t out[16]) {
    if (!data || !out) return -1;
    ripemd128_hash(data, len, out);
    return 0;
}

NEXTSSL_API int nextssl_root_legacy_unsafe_ripemd256(const uint8_t *data, size_t len,
                                                      uint8_t out[32]) {
    if (!data || !out) return -1;
    ripemd256_hash(data, len, out);
    return 0;
}

NEXTSSL_API int nextssl_root_legacy_unsafe_ripemd320(const uint8_t *data, size_t len,
                                                      uint8_t out[40]) {
    if (!data || !out) return -1;
    ripemd320_hash(data, len, out);
    return 0;
}
