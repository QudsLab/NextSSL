/**
 * @file root/core/root_cipher.h
 * @brief NextSSL Root â€” Explicit block cipher mode interface.
 *
 * Naming: nextssl_root_cipher_<mode>_{encrypt|decrypt}(...)
 *
 * All modes use AES-256 (key = 32 bytes), except:
 *   XTS : keys[64] (two AES-256 keys concatenated)
 *
 * Plaintext/ciphertext lengths must be a multiple of 16 for block modes
 * (CBC, ECB-style). Stream-derived modes (CTR, OFB, CFB) handle any length.
 *
 * Return: 0 on success, -1 on error.
 */

#ifndef NEXTSSL_ROOT_CIPHER_H
#define NEXTSSL_ROOT_CIPHER_H

#include <stddef.h>
#include <stdint.h>
#include "../../../../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------
 * AES-256-CBC  (PKCS#7 padding not applied â€” caller must pad)
 * ------------------------------------------------------------------ */
NEXTSSL_API int nextssl_root_cipher_aescbc_encrypt(const uint8_t key[32],
                                                    const uint8_t iv[16],
                                                    const uint8_t *pt, size_t pt_len,
                                                    uint8_t *ct);

NEXTSSL_API int nextssl_root_cipher_aescbc_decrypt(const uint8_t key[32],
                                                    const uint8_t iv[16],
                                                    const uint8_t *ct, size_t ct_len,
                                                    uint8_t *pt);

/* ------------------------------------------------------------------
 * AES-256-CFB  (8-bit segment; any plaintext length)
 * ------------------------------------------------------------------ */
NEXTSSL_API int nextssl_root_cipher_aescfb_encrypt(const uint8_t key[32],
                                                    const uint8_t iv[16],
                                                    const uint8_t *pt, size_t pt_len,
                                                    uint8_t *ct);

NEXTSSL_API int nextssl_root_cipher_aescfb_decrypt(const uint8_t key[32],
                                                    const uint8_t iv[16],
                                                    const uint8_t *ct, size_t ct_len,
                                                    uint8_t *pt);

/* ------------------------------------------------------------------
 * AES-256-CTR  (any plaintext length)
 * ------------------------------------------------------------------ */
NEXTSSL_API int nextssl_root_cipher_aesctr_encrypt(const uint8_t key[32],
                                                    const uint8_t iv[16],
                                                    const uint8_t *pt, size_t pt_len,
                                                    uint8_t *ct);

NEXTSSL_API int nextssl_root_cipher_aesctr_decrypt(const uint8_t key[32],
                                                    const uint8_t iv[16],
                                                    const uint8_t *ct, size_t ct_len,
                                                    uint8_t *pt);

/* ------------------------------------------------------------------
 * AES-256-OFB  (any plaintext length)
 * ------------------------------------------------------------------ */
NEXTSSL_API int nextssl_root_cipher_aesofb_encrypt(const uint8_t key[32],
                                                    const uint8_t iv[16],
                                                    const uint8_t *pt, size_t pt_len,
                                                    uint8_t *ct);

NEXTSSL_API int nextssl_root_cipher_aesofb_decrypt(const uint8_t key[32],
                                                    const uint8_t iv[16],
                                                    const uint8_t *ct, size_t ct_len,
                                                    uint8_t *pt);

/* ------------------------------------------------------------------
 * AES-256-XTS  (disk-sector encryption; keys[64] = two AES-256 keys)
 * tweak[16] = sector/block number as little-endian 128-bit integer.
 * Length must be >= 16 bytes.
 * ------------------------------------------------------------------ */
NEXTSSL_API int nextssl_root_cipher_aesxts_encrypt(const uint8_t keys[64],
                                                    const uint8_t tweak[16],
                                                    const uint8_t *pt, size_t pt_len,
                                                    uint8_t *ct);

NEXTSSL_API int nextssl_root_cipher_aesxts_decrypt(const uint8_t keys[64],
                                                    const uint8_t tweak[16],
                                                    const uint8_t *ct, size_t ct_len,
                                                    uint8_t *pt);

/* ------------------------------------------------------------------
 * AES-256-KW  (NIST key wrap â€” RFC 3394)
 * wrapped buffer must be secretLen + 8 bytes.
 * ------------------------------------------------------------------ */
NEXTSSL_API int nextssl_root_cipher_aeskw_wrap(const uint8_t kek[32],
                                                const uint8_t *secret, size_t secret_len,
                                                uint8_t *wrapped);

NEXTSSL_API int nextssl_root_cipher_aeskw_unwrap(const uint8_t kek[32],
                                                  const uint8_t *wrapped, size_t wrap_len,
                                                  uint8_t *secret);

/* ------------------------------------------------------------------
 * AES-256-FPE  (Format-Preserving Encryption â€” FF1 mode)
 * Operates over an alphabet-indexed plaintext.  pt and ct are the same
 * length; tweak is optional metadata (may be NULL with tweak_len = 0).
 * ------------------------------------------------------------------ */
NEXTSSL_API int nextssl_root_cipher_aesfpe_encrypt(const uint8_t key[32],
                                                    const uint8_t *tweak, size_t tweak_len,
                                                    const uint8_t *pt, size_t pt_len,
                                                    uint8_t *ct);

NEXTSSL_API int nextssl_root_cipher_aesfpe_decrypt(const uint8_t key[32],
                                                    const uint8_t *tweak, size_t tweak_len,
                                                    const uint8_t *ct, size_t ct_len,
                                                    uint8_t *pt);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_ROOT_CIPHER_H */
