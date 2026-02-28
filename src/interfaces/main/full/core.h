/**
 * @file core.h
 * @brief Layer 3: High-level core cryptographic operations
 * @layer main
 * @category core
 * @visibility public
 * 
 * Simplified, safe-by-default cryptographic operations for end users.
 * All functions use recommended algorithms with secure parameter choices.
 * 
 * **Capabilities:**
 * - Random number generation
 * - Key derivation (HKDF default)
 * - Authenticated encryption (AES-256-GCM default)
 * - Message authentication (HMAC-SHA256 default)
 * 
 * @security All operations use modern, secure defaults
 * @recommendations For specific algorithm needs, use Layer 2 (base) interfaces
 */

#ifndef NEXTSSL_MAIN_CORE_H
#define NEXTSSL_MAIN_CORE_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* ========== Random Number Generation ========== */

/**
 * Generate cryptographically secure random bytes
 * 
 * @param output Output buffer
 * @param length Number of bytes to generate
 * @return 0 on success, negative on error
 * 
 * @note Uses CTR-DRBG with automatic reseeding
 */
NEXTSSL_MAIN_API int nextssl_random(
    uint8_t *output,
    size_t length);

/* ========== Key Derivation ========== */

/**
 * Derive cryptographic key from input (HKDF-SHA256)
 * 
 * @param input_key Input keying material
 * @param input_len Length of input
 * @param context Optional context string (NULL if not used)
 * @param output_key Output buffer for derived key
 * @param output_len Desired output length
 * @return 0 on success, negative on error
 * 
 * @example Derive encryption key from shared secret
 */
NEXTSSL_MAIN_API int nextssl_derive_key(
    const uint8_t *input_key, size_t input_len,
    const char *context,
    uint8_t *output_key, size_t output_len);

/* ========== Authenticated Encryption ========== */

/**
 * Encrypt data with authentication (AES-256-GCM)
 * 
 * @param key 32-byte encryption key
 * @param plaintext Data to encrypt
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output buffer (allocate plaintext_len + 28 bytes)
 * @param ciphertext_len Output for actual ciphertext length (includes nonce + tag)
 * @return 0 on success, negative on error
 * 
 * @note Output format: [12-byte nonce][plaintext_len bytes ciphertext][16-byte tag]
 * @security Nonce generated automatically, never reused
 */
NEXTSSL_MAIN_API int nextssl_encrypt(
    const uint8_t key[32],
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t *ciphertext_len);

/**
 * Decrypt authenticated data (AES-256-GCM)
 * 
 * @param key 32-byte encryption key
 * @param ciphertext Ciphertext from nextssl_encrypt()
 * @param ciphertext_len Length of ciphertext
 * @param plaintext Output buffer (allocate ciphertext_len bytes)
 * @param plaintext_len Output for actual plaintext length
 * @return 0 on success, negative on error (including authentication failure)
 * 
 * @security Returns error if authentication fails - DO NOT use plaintext in that case
 */
NEXTSSL_MAIN_API int nextssl_decrypt(
    const uint8_t key[32],
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext, size_t *plaintext_len);

/* ========== Message Authentication ========== */

/**
 * Generate message authentication code (HMAC-SHA256)
 * 
 * @param key Authentication key
 * @param key_len Length of key
 * @param message Message to authenticate
 * @param message_len Length of message
 * @param mac Output buffer for MAC tag (32 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_MAIN_API int nextssl_mac(
    const uint8_t *key, size_t key_len,
    const uint8_t *message, size_t message_len,
    uint8_t mac[32]);

/**
 * Verify message authentication code (constant-time)
 * 
 * @param key Authentication key
 * @param key_len Length of key
 * @param message Message to verify
 * @param message_len Length of message
 * @param mac MAC tag to verify
 * @return 1 if valid, 0 if invalid, negative on error
 */
NEXTSSL_MAIN_API int nextssl_mac_verify(
    const uint8_t *key, size_t key_len,
    const uint8_t *message, size_t message_len,
    const uint8_t mac[32]);

/* ========== Secure Memory ========== */

/**
 * Securely zero sensitive data
 * 
 * @param data Buffer to zero
 * @param length Length of buffer
 * 
 * @note Use after handling keys, passwords, etc.
 */
NEXTSSL_MAIN_API void nextssl_secure_zero(
    void *data,
    size_t length);

/**
 * Constant-time memory comparison
 * 
 * @param a First buffer
 * @param b Second buffer
 * @param length Length to compare
 * @return 1 if equal, 0 if not equal
 */
NEXTSSL_MAIN_API int nextssl_constant_compare(
    const void *a,
    const void *b,
    size_t length);

#endif /* NEXTSSL_MAIN_CORE_H */
