/**
 * @file root/core/root_aead.h (Lite)
 * @brief NextSSL Root Lite -- Explicit AEAD interface.
 *
 * Lite build provides: AES-256-GCM, ChaCha20-Poly1305.
 *
 * Output layout for encrypt: [ciphertext][16-byte tag]
 * ct buffer must be at least plen + 16 bytes.
 * ct_len for decrypt must be plaintext_bytes + 16.
 *
 * @version 0.0.1-beta
 */

#ifndef NEXTSSL_LITE_ROOT_AEAD_H
#define NEXTSSL_LITE_ROOT_AEAD_H

#include <stddef.h>
#include <stdint.h>
#include "../../../../../config.h"  /* NEXTSSL_API */

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * AES-256-GCM
 * ========================================================================== */

NEXTSSL_API int nextssl_root_aead_aesgcm_encrypt(const uint8_t key[32],
                                                   const uint8_t nonce[12],
                                                   const uint8_t *aad, size_t aad_len,
                                                   const uint8_t *pt, size_t pt_len,
                                                   uint8_t *ct);

NEXTSSL_API int nextssl_root_aead_aesgcm_decrypt(const uint8_t key[32],
                                                   const uint8_t nonce[12],
                                                   const uint8_t *aad, size_t aad_len,
                                                   const uint8_t *ct, size_t ct_len,
                                                   uint8_t *pt);

/* ==========================================================================
 * ChaCha20-Poly1305
 * ========================================================================== */

NEXTSSL_API int nextssl_root_aead_chacha20_encrypt(const uint8_t key[32],
                                                    const uint8_t nonce[12],
                                                    const uint8_t *aad, size_t aad_len,
                                                    const uint8_t *pt, size_t pt_len,
                                                    uint8_t *ct);

NEXTSSL_API int nextssl_root_aead_chacha20_decrypt(const uint8_t key[32],
                                                    const uint8_t nonce[12],
                                                    const uint8_t *aad, size_t aad_len,
                                                    const uint8_t *ct, size_t ct_len,
                                                    uint8_t *pt);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_LITE_ROOT_AEAD_H */
