/**
 * @file aead.h
 * @brief Layer 3: High-level authenticated encryption
 * @layer main
 * @category aead
 * @visibility public
 * 
 * Simple authenticated encryption interface with automatic nonce handling.
 * 
 * **Default algorithm:** AES-256-GCM (hardware-accelerated)
 * **Alternative:** ChaCha20-Poly1305 (software-optimized)
 * 
 * @security Provides confidentiality + authenticity + integrity
 * @example Encrypt files, network traffic, database records
 */

#ifndef NEXTSSL_MAIN_AEAD_H
#define NEXTSSL_MAIN_AEAD_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* ========== AES-256-GCM (Default, Hardware-Accelerated) ========== */

/**
 * Encrypt data with authentication (AES-256-GCM)
 * 
 * @param key 32-byte encryption key
 * @param plaintext Data to encrypt
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output buffer (allocate plaintext_len + 28 bytes)
 * @param ciphertext_len Output for actual length
 * @return 0 on success, negative on error
 * 
 * @note Nonce automatically generated and prepended to output
 * @note Output format: [12-byte nonce][ciphertext][16-byte tag]
 * @security Safe for multiple encryptions with same key (nonce never reused)
 */
NEXTSSL_MAIN_API int nextssl_aead_encrypt(
    const uint8_t key[32],
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t *ciphertext_len);

/**
 * Decrypt authenticated data (AES-256-GCM)
 * 
 * @param key 32-byte encryption key
 * @param ciphertext Output from nextssl_aead_encrypt()
 * @param ciphertext_len Length of ciphertext
 * @param plaintext Output buffer (allocate ciphertext_len bytes)
 * @param plaintext_len Output for actual length
 * @return 0 on success, negative on error (including authentication failure)
 * 
 * @security Returns error if data was tampered with
 */
NEXTSSL_MAIN_API int nextssl_aead_decrypt(
    const uint8_t key[32],
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext, size_t *plaintext_len);

/* ========== ChaCha20-Poly1305 (Software-Optimized) ========== */

/**
 * Encrypt data with ChaCha20-Poly1305
 * 
 * @param key 32-byte encryption key
 * @param plaintext Data to encrypt
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output buffer (allocate plaintext_len + 28 bytes)
 * @param ciphertext_len Output for actual length
 * @return 0 on success, negative on error
 * 
 * @note Faster than AES-GCM in pure software (no hardware acceleration)
 * @note Output format: [12-byte nonce][ciphertext][16-byte tag]
 */
NEXTSSL_MAIN_API int nextssl_aead_chacha_encrypt(
    const uint8_t key[32],
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t *ciphertext_len);

/**
 * Decrypt ChaCha20-Poly1305 data
 * 
 * @param key 32-byte encryption key
 * @param ciphertext Output from nextssl_aead_chacha_encrypt()
 * @param ciphertext_len Length of ciphertext
 * @param plaintext Output buffer
 * @param plaintext_len Output for actual length
 * @return 0 on success, negative on error
 */
NEXTSSL_MAIN_API int nextssl_aead_chacha_decrypt(
    const uint8_t key[32],
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext, size_t *plaintext_len);

/* ========== Additional Authenticated Data (AAD) ========== */

/**
 * Encrypt with additional authenticated data
 * 
 * @param key 32-byte encryption key
 * @param plaintext Data to encrypt
 * @param plaintext_len Length of plaintext
 * @param aad Additional data to authenticate (not encrypted)
 * @param aad_len Length of AAD
 * @param ciphertext Output buffer (plaintext_len + 28 bytes)
 * @param ciphertext_len Output for actual length
 * @return 0 on success, negative on error
 * 
 * @example Encrypt payload, authenticate protocol headers
 */
NEXTSSL_MAIN_API int nextssl_aead_encrypt_with_aad(
    const uint8_t key[32],
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext, size_t *ciphertext_len);

/**
 * Decrypt with additional authenticated data
 * 
 * @param key 32-byte encryption key
 * @param ciphertext Ciphertext to decrypt
 * @param ciphertext_len Length of ciphertext
 * @param aad AAD from encryption (must match exactly)
 * @param aad_len Length of AAD
 * @param plaintext Output buffer
 * @param plaintext_len Output for actual length
 * @return 0 on success, negative on error
 */
NEXTSSL_MAIN_API int nextssl_aead_decrypt_with_aad(
    const uint8_t key[32],
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *plaintext, size_t *plaintext_len);

#endif /* NEXTSSL_MAIN_AEAD_H */
