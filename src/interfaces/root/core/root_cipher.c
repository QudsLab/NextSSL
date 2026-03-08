/**
 * @file root/core/root_cipher.c
 * @brief NextSSL Root — Block cipher mode implementation (all modes).
 */

#include "root_cipher.h"
#include "../root_internal.h"

#include "../../../primitives/cipher/aes_cbc/aes_cbc.h"
#include "../../../primitives/cipher/aes_cfb/aes_cfb.h"
#include "../../../primitives/cipher/aes_ctr/aes_ctr.h"
#include "../../../primitives/cipher/aes_ofb/aes_ofb.h"
#include "../../../primitives/cipher/aes_xts/aes_xts.h"
#include "../../../primitives/cipher/aes_kw/aes_kw.h"
#include "../../../primitives/cipher/aes_fpe/aes_fpe.h"

#ifndef NEXTSSL_BUILD_LITE

/* =========================================================================
 * AES-256-CBC
 * ====================================================================== */

NEXTSSL_API int nextssl_root_cipher_aescbc_encrypt(const uint8_t key[32],
                                                    const uint8_t iv[16],
                                                    const uint8_t *pt, size_t pt_len,
                                                    uint8_t *ct) {
    if (!key || !iv || !pt || !ct) return -1;
    return AES_CBC_encrypt(key, iv, pt, pt_len, ct) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_cipher_aescbc_decrypt(const uint8_t key[32],
                                                    const uint8_t iv[16],
                                                    const uint8_t *ct, size_t ct_len,
                                                    uint8_t *pt) {
    if (!key || !iv || !ct || !pt) return -1;
    return AES_CBC_decrypt(key, iv, ct, ct_len, pt) == 0 ? 0 : -1;
}

/* =========================================================================
 * AES-256-CFB
 * ====================================================================== */

NEXTSSL_API int nextssl_root_cipher_aescfb_encrypt(const uint8_t key[32],
                                                    const uint8_t iv[16],
                                                    const uint8_t *pt, size_t pt_len,
                                                    uint8_t *ct) {
    if (!key || !iv || !pt || !ct) return -1;
    /* AES_CFB_encrypt(key, block_t iVec, pntxt, ptextLen, crtxt) */
    AES_CFB_encrypt(key, iv, pt, pt_len, ct);
    return 0;
}

NEXTSSL_API int nextssl_root_cipher_aescfb_decrypt(const uint8_t key[32],
                                                    const uint8_t iv[16],
                                                    const uint8_t *ct, size_t ct_len,
                                                    uint8_t *pt) {
    if (!key || !iv || !ct || !pt) return -1;
    AES_CFB_decrypt(key, iv, ct, ct_len, pt);
    return 0;
}

/* =========================================================================
 * AES-256-CTR
 * ====================================================================== */

NEXTSSL_API int nextssl_root_cipher_aesctr_encrypt(const uint8_t key[32],
                                                    const uint8_t iv[16],
                                                    const uint8_t *pt, size_t pt_len,
                                                    uint8_t *ct) {
    if (!key || !iv || !pt || !ct) return -1;
    AES_CTR_encrypt(key, iv, pt, pt_len, ct);
    return 0;
}

NEXTSSL_API int nextssl_root_cipher_aesctr_decrypt(const uint8_t key[32],
                                                    const uint8_t iv[16],
                                                    const uint8_t *ct, size_t ct_len,
                                                    uint8_t *pt) {
    if (!key || !iv || !ct || !pt) return -1;
    AES_CTR_decrypt(key, iv, ct, ct_len, pt);
    return 0;
}

/* =========================================================================
 * AES-256-OFB
 * ====================================================================== */

NEXTSSL_API int nextssl_root_cipher_aesofb_encrypt(const uint8_t key[32],
                                                    const uint8_t iv[16],
                                                    const uint8_t *pt, size_t pt_len,
                                                    uint8_t *ct) {
    if (!key || !iv || !pt || !ct) return -1;
    /* AES_OFB_encrypt(key, block_t iVec, pntxt, ptextLen, crtxt) */
    AES_OFB_encrypt(key, iv, pt, pt_len, ct);
    return 0;
}

NEXTSSL_API int nextssl_root_cipher_aesofb_decrypt(const uint8_t key[32],
                                                    const uint8_t iv[16],
                                                    const uint8_t *ct, size_t ct_len,
                                                    uint8_t *pt) {
    if (!key || !iv || !ct || !pt) return -1;
    AES_OFB_decrypt(key, iv, ct, ct_len, pt);
    return 0;
}

/* =========================================================================
 * AES-256-XTS  (keys[64] = two AES-256 keys)
 * ====================================================================== */

NEXTSSL_API int nextssl_root_cipher_aesxts_encrypt(const uint8_t keys[64],
                                                    const uint8_t tweak[16],
                                                    const uint8_t *pt, size_t pt_len,
                                                    uint8_t *ct) {
    if (!keys || !tweak || !pt || !ct) return -1;
    return AES_XTS_encrypt(keys, tweak, pt, pt_len, ct) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_cipher_aesxts_decrypt(const uint8_t keys[64],
                                                    const uint8_t tweak[16],
                                                    const uint8_t *ct, size_t ct_len,
                                                    uint8_t *pt) {
    if (!keys || !tweak || !ct || !pt) return -1;
    return AES_XTS_decrypt(keys, tweak, ct, ct_len, pt) == 0 ? 0 : -1;
}

/* =========================================================================
 * AES-256-KW  (NIST Key Wrap — RFC 3394)
 * wrapped buffer must be secret_len + 8 bytes.
 * ====================================================================== */

NEXTSSL_API int nextssl_root_cipher_aeskw_wrap(const uint8_t kek[32],
                                                const uint8_t *secret, size_t secret_len,
                                                uint8_t *wrapped) {
    if (!kek || !secret || !wrapped || secret_len == 0) return -1;
    return AES_KEY_wrap(kek, secret, secret_len, wrapped) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_cipher_aeskw_unwrap(const uint8_t kek[32],
                                                  const uint8_t *wrapped, size_t wrap_len,
                                                  uint8_t *secret) {
    if (!kek || !wrapped || !secret || wrap_len < 8) return -1;
    return AES_KEY_unwrap(kek, wrapped, wrap_len, secret) == 0 ? 0 : -1;
}

/* =========================================================================
 * AES-256-FPE  (FF1 mode — format-preserving encryption)
 * Default FF_X = 1 (FF1).  tweak may be NULL with tweak_len = 0.
 * ====================================================================== */

#ifndef FF_X
#define FF_X 1
#endif

NEXTSSL_API int nextssl_root_cipher_aesfpe_encrypt(const uint8_t key[32],
                                                    const uint8_t *tweak, size_t tweak_len,
                                                    const uint8_t *pt, size_t pt_len,
                                                    uint8_t *ct) {
    if (!key || !pt || !ct || pt_len == 0) return -1;
    return AES_FPE_encrypt(key, (uint8_t *)tweak, tweak_len, pt, pt_len, ct) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_cipher_aesfpe_decrypt(const uint8_t key[32],
                                                    const uint8_t *tweak, size_t tweak_len,
                                                    const uint8_t *ct, size_t ct_len,
                                                    uint8_t *pt) {
    if (!key || !ct || !pt || ct_len == 0) return -1;
    return AES_FPE_decrypt(key, (uint8_t *)tweak, tweak_len, ct, ct_len, pt) == 0 ? 0 : -1;
}

#endif /* NEXTSSL_BUILD_LITE */