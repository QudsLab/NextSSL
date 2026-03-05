/**
 * @file root/core/root_aead.c (Lite)
 * @brief NextSSL Root Lite -- AEAD implementations.
 */

#ifndef NEXTSSL_BUILDING_DLL
#define NEXTSSL_BUILDING_DLL
#endif

#include "root_aead.h"
#include "../../../../../primitives/aead/aes_gcm/aes_gcm.h"
#include "../../../../../primitives/aead/chacha20_poly1305/chacha20_poly1305.h"

/* ==========================================================================
 * AES-256-GCM
 * ========================================================================== */

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

/* ==========================================================================
 * ChaCha20-Poly1305
 * ========================================================================== */

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
