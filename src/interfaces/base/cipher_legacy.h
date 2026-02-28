/**
 * @file cipher_legacy.h
 * @brief Layer 2: Legacy cipher aggregation
 * @layer base
 * @category cipher
 * @visibility semi-public
 * 
 * Legacy unauthenticated ciphers provided ONLY for compatibility.
 * 
 * ⚠️  **SECURITY WARNING** ⚠️
 * These ciphers provide NO authentication - vulnerable to tampering.
 * 
 * **DO NOT USE for new applications**
 * Use aead_modern.h interfaces (AES-GCM, ChaCha20-Poly1305) instead.
 * 
 * **Provided for compatibility ONLY:**
 * - AES-CBC (legacy TLS, disk encryption)
 * - AES-CTR (legacy systems)
 * - 3DES (ancient legacy only)
 * 
 * @warning These functions log security warnings and require explicit opt-in
 */

#ifndef NEXTSSL_BASE_CIPHER_LEGACY_H
#define NEXTSSL_BASE_CIPHER_LEGACY_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* ========== AES-256-CBC (DEPRECATED) ========== */

/**
 * AES-256-CBC encryption (DEPRECATED - no authentication)
 * 
 * @param key 256-bit key (32 bytes)
 * @param iv Initialization vector (16 bytes, must be random)
 * @param plaintext Plaintext (must be multiple of 16 bytes after padding)
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output buffer (same length as plaintext)
 * @return 0 on success, negative on error
 * 
 * @deprecated Use AES-256-GCM instead
 * @warning NO authentication - vulnerable to padding oracle, bit-flipping
 * @warning Caller must apply PKCS#7 padding
 * @use_case Legacy protocol compatibility ONLY
 */
NEXTSSL_BASE_API int nextssl_base_cipher_legacy_aes256cbc_encrypt(
    const uint8_t key[32],
    const uint8_t iv[16],
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext) __attribute__((deprecated));

/**
 * AES-256-CBC decryption
 * 
 * @param key 256-bit key (32 bytes)
 * @param iv Initialization vector (16 bytes)
 * @param ciphertext Ciphertext (multiple of 16 bytes)
 * @param ciphertext_len Length of ciphertext
 * @param plaintext Output buffer
 * @return 0 on success, negative on error
 * 
 * @deprecated Use AES-256-GCM instead
 * @warning NO authentication - attacker can modify ciphertext
 * @warning Caller must handle PKCS#7 padding removal
 */
NEXTSSL_BASE_API int nextssl_base_cipher_legacy_aes256cbc_decrypt(
    const uint8_t key[32],
    const uint8_t iv[16],
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext) __attribute__((deprecated));

/* ========== AES-256-CTR (DEPRECATED) ========== */

/**
 * AES-256-CTR encryption (DEPRECATED - no authentication)
 * 
 * @param key 256-bit key (32 bytes)
 * @param nonce Nonce/counter (16 bytes, must be unique)
 * @param plaintext Plaintext
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output buffer
 * @return 0 on success, negative on error
 * 
 * @deprecated Use ChaCha20-Poly1305 instead
 * @warning NO authentication - vulnerable to bit-flipping
 * @warning NEVER reuse nonce with same key
 * @note Encryption and decryption are the same operation
 */
NEXTSSL_BASE_API int nextssl_base_cipher_legacy_aes256ctr(
    const uint8_t key[32],
    const uint8_t nonce[16],
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext) __attribute__((deprecated));

/* ========== 3DES (BROKEN - 64-bit block size) ========== */

/**
 * 3DES-EDE3-CBC encryption (BROKEN - DO NOT USE)
 * 
 * @param key 192-bit key (24 bytes, 3x 64-bit DES keys)
 * @param iv Initialization vector (8 bytes)
 * @param plaintext Plaintext (multiple of 8 bytes after padding)
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output buffer
 * @return 0 on success, negative on error
 * 
 * @deprecated Use AES-256-GCM instead
 * @warning 64-bit block size - vulnerable to Sweet32 attack
 * @warning NO authentication
 * @warning Slow and insecure
 * @use_case Ancient legacy systems ONLY (pre-2000)
 */
NEXTSSL_BASE_API int nextssl_base_cipher_legacy_3des_encrypt(
    const uint8_t key[24],
    const uint8_t iv[8],
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext) __attribute__((deprecated));

/**
 * 3DES-EDE3-CBC decryption
 * 
 * @param key 192-bit key (24 bytes)
 * @param iv Initialization vector (8 bytes)
 * @param ciphertext Ciphertext (multiple of 8 bytes)
 * @param ciphertext_len Length of ciphertext
 * @param plaintext Output buffer
 * @return 0 on success, negative on error
 * 
 * @deprecated Use AES-256-GCM instead
 */
NEXTSSL_BASE_API int nextssl_base_cipher_legacy_3des_decrypt(
    const uint8_t key[24],
    const uint8_t iv[8],
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext) __attribute__((deprecated));

/**
 * Self-test for legacy cipher operations
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_BASE_API int nextssl_base_cipher_legacy_selftest(void);

#endif /* NEXTSSL_BASE_CIPHER_LEGACY_H */
