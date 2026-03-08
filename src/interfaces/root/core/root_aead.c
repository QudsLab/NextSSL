/**
 * @file root/core/root_aead.c
 * @brief NextSSL Root — AEAD implementation (all algorithms).
 *
 * Output layout for all standard AEAD encrypt: [ciphertext][16-byte tag].
 * ct buffer must be plen + 16 bytes.
 */

#include "root_aead.h"
#include "../root_internal.h"

#include "../../../primitives/aead/aes_gcm/aes_gcm.h"
#ifndef NEXTSSL_BUILD_LITE
#include "../../../primitives/aead/aes_ccm/aes_ccm.h"
#include "../../../primitives/aead/aes_eax/aes_eax.h"
#include "../../../primitives/aead/aes_gcm_siv/aes_gcm_siv.h"
#include "../../../primitives/aead/aes_ocb/aes_ocb.h"
#include "../../../primitives/aead/aes_siv/aes_siv.h"
#include "../../../primitives/aead/aes_poly1305/aes_poly1305.h"
#endif /* NEXTSSL_BUILD_LITE */
#include "../../../primitives/aead/chacha20_poly1305/chacha20_poly1305.h"

/* =========================================================================
 * AES-256-GCM
 * ====================================================================== */

NEXTSSL_API int nextssl_root_aead_aesgcm_encrypt(const uint8_t key[32],
                                                   const uint8_t nonce[12],
                                                   const uint8_t *aad, size_t aad_len,
                                                   const uint8_t *pt, size_t pt_len,
                                                   uint8_t *ct) {
    if (!key || !nonce || !ct) return -1;
    if (pt_len > 0 && !pt) return -1;
    AES_GCM_encrypt((uint8_t *)key, (uint8_t *)nonce,
                    (void *)aad, aad_len,
                    (uint8_t *)pt, (int)pt_len, ct);
    return 0;
}

NEXTSSL_API int nextssl_root_aead_aesgcm_decrypt(const uint8_t key[32],
                                                   const uint8_t nonce[12],
                                                   const uint8_t *aad, size_t aad_len,
                                                   const uint8_t *ct, size_t ct_len,
                                                   uint8_t *pt) {
    if (!key || !nonce || !ct || !pt || ct_len < 16) return -1;
    return AES_GCM_decrypt((uint8_t *)key, (uint8_t *)nonce,
                           (void *)aad, aad_len,
                           (uint8_t *)ct, ct_len - 16, pt) == 0 ? 0 : -1;
}

/* =========================================================================
 * AES-256-CCM
 * ====================================================================== */

#ifndef NEXTSSL_BUILD_LITE

NEXTSSL_API int nextssl_root_aead_aesccm_encrypt(const uint8_t key[32],
                                                   const uint8_t nonce[12],
                                                   const uint8_t *aad, size_t aad_len,
                                                   const uint8_t *pt, size_t pt_len,
                                                   uint8_t *ct) {
    if (!key || !nonce || !ct) return -1;
    if (pt_len > 0 && !pt) return -1;
    AES_CCM_encrypt((uint8_t *)key, (uint8_t *)nonce,
                    (void *)aad, aad_len,
                    (uint8_t *)pt, pt_len, ct);
    return 0;
}

NEXTSSL_API int nextssl_root_aead_aesccm_decrypt(const uint8_t key[32],
                                                   const uint8_t nonce[12],
                                                   const uint8_t *aad, size_t aad_len,
                                                   const uint8_t *ct, size_t ct_len,
                                                   uint8_t *pt) {
    if (!key || !nonce || !ct || !pt || ct_len < 16) return -1;
    return AES_CCM_decrypt((uint8_t *)key, (uint8_t *)nonce,
                           (void *)aad, aad_len,
                           (uint8_t *)ct, ct_len - 16, pt) == 0 ? 0 : -1;
}

/* =========================================================================
 * AES-256-EAX
 * ====================================================================== */

NEXTSSL_API int nextssl_root_aead_aeseax_encrypt(const uint8_t key[32],
                                                   const uint8_t nonce[12],
                                                   const uint8_t *aad, size_t aad_len,
                                                   const uint8_t *pt, size_t pt_len,
                                                   uint8_t *ct) {
    if (!key || !nonce || !ct) return -1;
    if (pt_len > 0 && !pt) return -1;
    AES_EAX_encrypt((uint8_t *)key, (uint8_t *)nonce,
                    (void *)aad, aad_len,
                    (uint8_t *)pt, pt_len, ct);
    return 0;
}

NEXTSSL_API int nextssl_root_aead_aeseax_decrypt(const uint8_t key[32],
                                                   const uint8_t nonce[12],
                                                   const uint8_t *aad, size_t aad_len,
                                                   const uint8_t *ct, size_t ct_len,
                                                   uint8_t *pt) {
    if (!key || !nonce || !ct || !pt || ct_len < 16) return -1;
    return AES_EAX_decrypt((uint8_t *)key, (uint8_t *)nonce,
                           (void *)aad, aad_len,
                           (uint8_t *)ct, ct_len - 16, pt) == 0 ? 0 : -1;
}

/* =========================================================================
 * AES-256-GCM-SIV
 * ====================================================================== */

NEXTSSL_API int nextssl_root_aead_aesgcmsiv_encrypt(const uint8_t key[32],
                                                      const uint8_t nonce[12],
                                                      const uint8_t *aad, size_t aad_len,
                                                      const uint8_t *pt, size_t pt_len,
                                                      uint8_t *ct) {
    if (!key || !nonce || !ct) return -1;
    if (pt_len > 0 && !pt) return -1;
    GCM_SIV_encrypt((uint8_t *)key, (uint8_t *)nonce,
                    (void *)aad, aad_len,
                    (uint8_t *)pt, pt_len, ct);
    return 0;
}

NEXTSSL_API int nextssl_root_aead_aesgcmsiv_decrypt(const uint8_t key[32],
                                                      const uint8_t nonce[12],
                                                      const uint8_t *aad, size_t aad_len,
                                                      const uint8_t *ct, size_t ct_len,
                                                      uint8_t *pt) {
    if (!key || !nonce || !ct || !pt || ct_len < 16) return -1;
    return GCM_SIV_decrypt((uint8_t *)key, (uint8_t *)nonce,
                           (void *)aad, aad_len,
                           (uint8_t *)ct, ct_len - 16, pt) == 0 ? 0 : -1;
}

/* =========================================================================
 * AES-256-OCB
 * ====================================================================== */

NEXTSSL_API int nextssl_root_aead_aesocb_encrypt(const uint8_t key[32],
                                                   const uint8_t nonce[12],
                                                   const uint8_t *aad, size_t aad_len,
                                                   const uint8_t *pt, size_t pt_len,
                                                   uint8_t *ct) {
    if (!key || !nonce || !ct) return -1;
    if (pt_len > 0 && !pt) return -1;
    AES_OCB_encrypt((uint8_t *)key, (uint8_t *)nonce,
                    (void *)aad, aad_len,
                    (uint8_t *)pt, pt_len, ct);
    return 0;
}

NEXTSSL_API int nextssl_root_aead_aesocb_decrypt(const uint8_t key[32],
                                                   const uint8_t nonce[12],
                                                   const uint8_t *aad, size_t aad_len,
                                                   const uint8_t *ct, size_t ct_len,
                                                   uint8_t *pt) {
    if (!key || !nonce || !ct || !pt || ct_len < 16) return -1;
    return AES_OCB_decrypt((uint8_t *)key, (uint8_t *)nonce,
                           (void *)aad, aad_len,
                           (uint8_t *)ct, ct_len - 16, pt) == 0 ? 0 : -1;
}

/* =========================================================================
 * AES-256-SIV  (deterministic AEAD — no nonce)
 * keys[64] = two 32-byte AES-256 keys concatenated.
 * Encrypt writes synthetic IV to iv_out[16] and ciphertext to ct.
 * ====================================================================== */

NEXTSSL_API int nextssl_root_aead_aessiv_encrypt(const uint8_t keys[64],
                                                   const uint8_t *aad, size_t aad_len,
                                                   const uint8_t *pt, size_t pt_len,
                                                   uint8_t iv_out[16],
                                                   uint8_t *ct) {
    if (!keys || !iv_out || !ct) return -1;
    if (pt_len > 0 && !pt) return -1;
    /* AES_SIV_encrypt: (keys, aData, aDataLen, pntxt, ptextLen, iv_block, crtxt) */
    AES_SIV_encrypt(keys, (void *)aad, aad_len,
                    (void *)pt, pt_len,
                    iv_out, ct);
    return 0;
}

NEXTSSL_API int nextssl_root_aead_aessiv_decrypt(const uint8_t keys[64],
                                                   const uint8_t iv[16],
                                                   const uint8_t *aad, size_t aad_len,
                                                   const uint8_t *ct, size_t ct_len,
                                                   uint8_t *pt) {
    if (!keys || !iv || !ct || !pt) return -1;
    return AES_SIV_decrypt(keys, iv,
                           (void *)aad, aad_len,
                           (void *)ct, ct_len, pt) == 0 ? 0 : -1;
}

/* =========================================================================
 * AES-256-Poly1305  (one-shot MAC; not encrypt/decrypt)
 * keys[48]: first 32 bytes = AES key, last 16 bytes = Poly1305 key.
 * nonce[16]: 16-byte block nonce.
 * mac[16]: 16-byte authentication tag output.
 * ====================================================================== */

NEXTSSL_API int nextssl_root_aead_aespoly1305(const uint8_t keys[48],
                                               const uint8_t nonce[16],
                                               const uint8_t *data, size_t data_len,
                                               uint8_t mac[16]) {
    if (!keys || !nonce || !mac) return -1;
    if (data_len > 0 && !data) return -1;
    /* AES_Poly1305(keys, block_t nonce, data, dataSize, block_t mac_out) */
    AES_Poly1305(keys, nonce, (void *)data, data_len, mac);
    return 0;
}

#endif /* NEXTSSL_BUILD_LITE */

/* =========================================================================
 * ChaCha20-Poly1305
 * ====================================================================== */

NEXTSSL_API int nextssl_root_aead_chacha20_encrypt(const uint8_t key[32],
                                                    const uint8_t nonce[12],
                                                    const uint8_t *aad, size_t aad_len,
                                                    const uint8_t *pt, size_t pt_len,
                                                    uint8_t *ct) {
    if (!key || !nonce || !ct) return -1;
    if (pt_len > 0 && !pt) return -1;
    ChaCha20_Poly1305_encrypt((uint8_t *)key, (uint8_t *)nonce,
                              (void *)aad, aad_len,
                              (uint8_t *)pt, (int)pt_len, ct);
    return 0;
}

NEXTSSL_API int nextssl_root_aead_chacha20_decrypt(const uint8_t key[32],
                                                    const uint8_t nonce[12],
                                                    const uint8_t *aad, size_t aad_len,
                                                    const uint8_t *ct, size_t ct_len,
                                                    uint8_t *pt) {
    if (!key || !nonce || !ct || !pt || ct_len < 16) return -1;
    return ChaCha20_Poly1305_decrypt((uint8_t *)key, (uint8_t *)nonce,
                                     (void *)aad, aad_len,
                                     (uint8_t *)ct, ct_len, pt) == 0 ? 0 : -1;
}
