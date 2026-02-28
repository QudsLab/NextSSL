/**
 * @file aead_modern.h
 * @brief Layer 2: Modern AEAD cipher aggregation
 * @layer base
 * @category aead
 * @visibility semi-public
 * 
 * Modern authenticated encryption with associated data (AEAD) ciphers only.
 * 
 * **Ciphers provided:**
 * - AES-256-GCM (recommended, hardware-accelerated)
 * - ChaCha20-Poly1305 (recommended for software)
 * - AES-256-GCM-SIV (nonce-misuse resistant)
 * 
 * @warning For legacy ciphers (AES-CBC, etc.), see cipher_legacy.h
 * @security All ciphers provide confidentiality + authenticity + integrity
 */

#ifndef NEXTSSL_BASE_AEAD_MODERN_H
#define NEXTSSL_BASE_AEAD_MODERN_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* ========== AES-256-GCM (RECOMMENDED) ========== */

/**
 * AES-256-GCM encryption
 * 
 * @param key 256-bit key (32 bytes)
 * @param nonce Nonce (12 bytes recommended, MUST be unique per key)
 * @param nonce_len Length of nonce (8-16 bytes)
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len Length of AAD
 * @param plaintext Plaintext to encrypt
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output buffer (same length as plaintext)
 * @param tag Output authentication tag (16 bytes)
 * @return 0 on success, negative on error
 * 
 * @warning NEVER reuse nonce with same key
 * @security Hardware-accelerated on modern CPUs
 */
NEXTSSL_BASE_API int nextssl_base_aead_aes256gcm_encrypt(
    const uint8_t key[32],
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext,
    uint8_t tag[16]);

/**
 * AES-256-GCM decryption
 * 
 * @param key 256-bit key (32 bytes)
 * @param nonce Nonce from encryption
 * @param nonce_len Length of nonce
 * @param aad AAD from encryption (must match)
 * @param aad_len Length of AAD
 * @param ciphertext Ciphertext to decrypt
 * @param ciphertext_len Length of ciphertext
 * @param tag Authentication tag from encryption (16 bytes)
 * @param plaintext Output buffer
 * @return 1 if authenticated, 0 if auth failed, negative on error
 * 
 * @security DO NOT use plaintext if return value is 0
 */
NEXTSSL_BASE_API int nextssl_base_aead_aes256gcm_decrypt(
    const uint8_t key[32],
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t tag[16],
    uint8_t *plaintext);

/* ========== ChaCha20-Poly1305 (RECOMMENDED for software) ========== */

/**
 * ChaCha20-Poly1305 encryption
 * 
 * @param key 256-bit key (32 bytes)
 * @param nonce Nonce (12 bytes, MUST be unique per key)
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len Length of AAD
 * @param plaintext Plaintext to encrypt
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output buffer
 * @param tag Output authentication tag (16 bytes)
 * @return 0 on success, negative on error
 * 
 * @warning NEVER reuse nonce with same key
 * @security Fast in software, no timing side-channels
 */
NEXTSSL_BASE_API int nextssl_base_aead_chacha20poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext,
    uint8_t tag[16]);

/**
 * ChaCha20-Poly1305 decryption
 * 
 * @param key 256-bit key (32 bytes)
 * @param nonce Nonce from encryption (12 bytes)
 * @param aad AAD from encryption
 * @param aad_len Length of AAD
 * @param ciphertext Ciphertext to decrypt
 * @param ciphertext_len Length of ciphertext
 * @param tag Authentication tag from encryption (16 bytes)
 * @param plaintext Output buffer
 * @return 1 if authenticated, 0 if auth failed, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_aead_chacha20poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t tag[16],
    uint8_t *plaintext);

/* ========== AES-256-GCM-SIV (Nonce-misuse resistant) ========== */

/**
 * AES-256-GCM-SIV encryption (nonce-misuse resistant)
 * 
 * @param key 256-bit key (32 bytes)
 * @param nonce Nonce (12 bytes, can tolerate occasional reuse)
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len Length of AAD
 * @param plaintext Plaintext to encrypt
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output buffer
 * @param tag Output authentication tag (16 bytes)
 * @return 0 on success, negative on error
 * 
 * @note More forgiving of nonce reuse than GCM, but still try to avoid it
 * @security Deterministic for same (key, nonce, plaintext, aad)
 */
NEXTSSL_BASE_API int nextssl_base_aead_aes256gcmsiv_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext,
    uint8_t tag[16]);

/**
 * AES-256-GCM-SIV decryption
 * 
 * @param key 256-bit key (32 bytes)
 * @param nonce Nonce from encryption (12 bytes)
 * @param aad AAD from encryption
 * @param aad_len Length of AAD
 * @param ciphertext Ciphertext to decrypt
 * @param ciphertext_len Length of ciphertext
 * @param tag Authentication tag from encryption (16 bytes)
 * @param plaintext Output buffer
 * @return 1 if authenticated, 0 if auth failed, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_aead_aes256gcmsiv_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t tag[16],
    uint8_t *plaintext);

/**
 * Self-test for AEAD operations
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_BASE_API int nextssl_base_aead_modern_selftest(void);

#endif /* NEXTSSL_BASE_AEAD_MODERN_H */
