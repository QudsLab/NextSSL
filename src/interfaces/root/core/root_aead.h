/**
 * @file root/core/root_aead.h
 * @brief NextSSL Root — Explicit AEAD algorithm interface.
 *
 * Naming: nextssl_root_aead_<algorithm>_{encrypt|decrypt}(...)
 *
 * Output layout for all encrypt functions:
 *   ct buffer = [ciphertext (plen bytes)][16-byte authentication tag]
 *   → caller must allocate plen + 16 bytes.
 *
 * For decrypt: clen = plaintext_len + 16 (includes tag).
 * Returns 0 on success, -1 on failure (including tag mismatch).
 *
 * AES variants all use AES-256 (key = 32 bytes).
 * Nonce sizes:
 *   GCM, CCM, EAX, GCM-SIV, OCB : 12 bytes
 *   SIV  : no nonce (deterministic); uses 64-byte dual key; iv[16] is output
 *   Poly1305 : nonce = 16-byte block, mac is separate output
 */

#ifndef NEXTSSL_ROOT_AEAD_H
#define NEXTSSL_ROOT_AEAD_H

#include <stddef.h>
#include <stdint.h>
#include "../../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------
 * AES-256-GCM
 * ------------------------------------------------------------------ */
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

#ifndef NEXTSSL_BUILD_LITE
/* ------------------------------------------------------------------
 * AES-256-CCM
 * ------------------------------------------------------------------ */
NEXTSSL_API int nextssl_root_aead_aesccm_encrypt(const uint8_t key[32],
                                                  const uint8_t nonce[12],
                                                  const uint8_t *aad, size_t aad_len,
                                                  const uint8_t *pt, size_t pt_len,
                                                  uint8_t *ct);

NEXTSSL_API int nextssl_root_aead_aesccm_decrypt(const uint8_t key[32],
                                                  const uint8_t nonce[12],
                                                  const uint8_t *aad, size_t aad_len,
                                                  const uint8_t *ct, size_t ct_len,
                                                  uint8_t *pt);

/* ------------------------------------------------------------------
 * AES-256-EAX
 * ------------------------------------------------------------------ */
NEXTSSL_API int nextssl_root_aead_aeseax_encrypt(const uint8_t key[32],
                                                  const uint8_t nonce[12],
                                                  const uint8_t *aad, size_t aad_len,
                                                  const uint8_t *pt, size_t pt_len,
                                                  uint8_t *ct);

NEXTSSL_API int nextssl_root_aead_aeseax_decrypt(const uint8_t key[32],
                                                  const uint8_t nonce[12],
                                                  const uint8_t *aad, size_t aad_len,
                                                  const uint8_t *ct, size_t ct_len,
                                                  uint8_t *pt);

/* ------------------------------------------------------------------
 * AES-256-GCM-SIV
 * ------------------------------------------------------------------ */
NEXTSSL_API int nextssl_root_aead_aesgcmsiv_encrypt(const uint8_t key[32],
                                                     const uint8_t nonce[12],
                                                     const uint8_t *aad, size_t aad_len,
                                                     const uint8_t *pt, size_t pt_len,
                                                     uint8_t *ct);

NEXTSSL_API int nextssl_root_aead_aesgcmsiv_decrypt(const uint8_t key[32],
                                                     const uint8_t nonce[12],
                                                     const uint8_t *aad, size_t aad_len,
                                                     const uint8_t *ct, size_t ct_len,
                                                     uint8_t *pt);

/* ------------------------------------------------------------------
 * AES-256-OCB
 * ------------------------------------------------------------------ */
NEXTSSL_API int nextssl_root_aead_aesocb_encrypt(const uint8_t key[32],
                                                  const uint8_t nonce[12],
                                                  const uint8_t *aad, size_t aad_len,
                                                  const uint8_t *pt, size_t pt_len,
                                                  uint8_t *ct);

NEXTSSL_API int nextssl_root_aead_aesocb_decrypt(const uint8_t key[32],
                                                  const uint8_t nonce[12],
                                                  const uint8_t *aad, size_t aad_len,
                                                  const uint8_t *ct, size_t ct_len,
                                                  uint8_t *pt);

/* ------------------------------------------------------------------
 * AES-256-SIV  (deterministic; nonce-misuse resistant)
 * Requires 64-byte dual key (two 32-byte AES keys concatenated).
 * Encrypt outputs: [16-byte synthetic IV][ciphertext].
 * Decrypt: iv[16] is the synthetic IV prepended by encrypt.
 * ------------------------------------------------------------------ */
NEXTSSL_API int nextssl_root_aead_aessiv_encrypt(const uint8_t keys[64],
                                                  const uint8_t *aad, size_t aad_len,
                                                  const uint8_t *pt, size_t pt_len,
                                                  uint8_t iv_out[16],
                                                  uint8_t *ct);

NEXTSSL_API int nextssl_root_aead_aessiv_decrypt(const uint8_t keys[64],
                                                  const uint8_t iv[16],
                                                  const uint8_t *aad, size_t aad_len,
                                                  const uint8_t *ct, size_t ct_len,
                                                  uint8_t *pt);

/* ------------------------------------------------------------------
 * AES-256-Poly1305 (one-shot MAC; keys[48] = 32-byte AES + 16-byte Poly key)
 * Produces a 16-byte MAC tag; not an AEAD encrypt/decrypt pair.
 * ------------------------------------------------------------------ */
NEXTSSL_API int nextssl_root_aead_aespoly1305(const uint8_t keys[48],
                                               const uint8_t nonce[16],
                                               const uint8_t *data, size_t data_len,
                                               uint8_t mac[16]);

#endif /* NEXTSSL_BUILD_LITE */

/* ------------------------------------------------------------------
 * ChaCha20-Poly1305
 * ------------------------------------------------------------------ */
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

#endif /* NEXTSSL_ROOT_AEAD_H */
