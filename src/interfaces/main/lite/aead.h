/**
 * @file aead_lite.h
 * @brief Lite variant AEAD API (AES-256-GCM, ChaCha20-Poly1305 only)
 * @version 0.1.0-beta-lite
 * @date 2026-02-28
 */

#ifndef NEXTSSL_MAIN_LITE_AEAD_H
#define NEXTSSL_MAIN_LITE_AEAD_H

#include "../../../config.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief AEAD algorithms available in lite variant
 */
typedef enum {
    NEXTSSL_LITE_AEAD_AES256GCM,         /**< AES-256-GCM (NIST) */
    NEXTSSL_LITE_AEAD_CHACHA20POLY1305   /**< ChaCha20-Poly1305 (RFC 8439) */
} nextssl_lite_aead_algorithm_t;

/**
 * @brief Encrypt and authenticate data (AEAD)
 * 
 * Supported algorithms:
 * - "AES-256-GCM" (default) - 32-byte key, 12-byte nonce
 * - "ChaCha20-Poly1305" - 32-byte key, 12-byte nonce
 * 
 * @param algorithm Algorithm name (NULL defaults to AES-256-GCM)
 * @param key Encryption key (32 bytes)
 * @param nonce Nonce/IV (12 bytes, must be unique per key)
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len AAD length
 * @param plaintext Input plaintext
 * @param plaintext_len Plaintext length
 * @param ciphertext Output buffer (plaintext_len + 16 bytes for tag)
 * @return 0 on success, negative on error
 */
NEXTSSL_API int nextssl_lite_aead_encrypt(
    const char *algorithm,
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext
);

/**
 * @brief Decrypt and verify authenticated data (AEAD)
 * 
 * @param algorithm Algorithm name (NULL defaults to AES-256-GCM)
 * @param key Decryption key (32 bytes)
 * @param nonce Nonce/IV (12 bytes)
 * @param aad Additional authenticated data
 * @param aad_len AAD length
 * @param ciphertext Input ciphertext (includes 16-byte tag)
 * @param ciphertext_len Ciphertext length (plaintext + 16)
 * @param plaintext Output buffer (ciphertext_len - 16 bytes)
 * @return 0 on success, negative on error
 * 
 * @retval 0 Success, plaintext decrypted and authenticated
 * @retval -NEXTSSL_ERROR_AUTH_FAILED Authentication tag mismatch
 */
NEXTSSL_API int nextssl_lite_aead_decrypt(
    const char *algorithm,
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext
);

/**
 * @brief Get AEAD tag size
 * 
 * @param algorithm Algorithm name
 * @return Tag size in bytes (16 for both GCM and Poly1305)
 */
NEXTSSL_API int nextssl_lite_aead_tag_size(const char *algorithm);

/**
 * @brief Check if AEAD algorithm is available
 * 
 * @param algorithm Algorithm name
 * @return 1 if available, 0 otherwise
 */
NEXTSSL_API int nextssl_lite_aead_available(const char *algorithm);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_MAIN_LITE_AEAD_H */
