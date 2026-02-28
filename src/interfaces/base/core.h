/**
 * @file core.h
 * @brief Layer 2: Core cryptographic primitives aggregation
 * @layer base
 * @category core
 * @visibility semi-public
 * 
 * Aggregates fundamental cryptographic operations from Layer 1 partial interfaces
 * with comprehensive input validation, safe defaults, and error handling.
 * 
 * **Functions provided:**
 * - Random number generation (DRBG-based)
 * - Key derivation (HKDF, Argon2)
 * - HMAC operations (SHA-256/512)
 * - Authenticated encryption (AES-GCM, ChaCha20-Poly1305)
 * - Secure buffer operations
 * 
 * @security All operations use validated parameters and constant-time where applicable
 */

#ifndef NEXTSSL_BASE_CORE_H
#define NEXTSSL_BASE_CORE_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* ========== Random Number Generation ========== */

/**
 * Generate cryptographically secure random bytes
 * 
 * @param out Output buffer
 * @param len Number of bytes to generate (1-1048576 max)
 * @return 0 on success, negative on error
 * 
 * @note Uses CTR-DRBG reseeded from system entropy
 * @validation Validates output buffer and length
 */
NEXTSSL_BASE_API int nextssl_base_core_random(
    uint8_t *out,
    size_t len);

/* ========== Key Derivation ========== */

/**
 * HKDF key derivation (RFC 5869) with SHA-256
 * 
 * @param ikm Input keying material
 * @param ikm_len Length of IKM (1-32768 bytes)
 * @param salt Optional salt (NULL if not used)
 * @param salt_len Length of salt
 * @param info Optional context/application info (NULL if not used)
 * @param info_len Length of info
 * @param okm Output keying material buffer
 * @param okm_len Desired length of output (1-8160 bytes)
 * @return 0 on success, negative on error
 * 
 * @validation Input parameters validated for length and non-NULL
 * @note Recommended for most key derivation use cases
 */
NEXTSSL_BASE_API int nextssl_base_core_hkdf_sha256(
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len);

/**
 * Argon2id key derivation (password-based, memory-hard)
 * 
 * @param password Input password
 * @param password_len Length of password (1-2^32-1 bytes)
 * @param salt Salt (16+ bytes recommended)
 * @param salt_len Length of salt (8-64 bytes)
 * @param t_cost Time cost (3-10 recommended)
 * @param m_cost Memory cost in KiB (65536-1048576 recommended)
 * @param parallelism Threads (1-4 recommended)
 * @param derived_key Output buffer
 * @param derived_key_len Desired output length (16-64 bytes typical)
 * @return 0 on success, negative on error
 * 
 * @validation All parameters validated for sensible ranges
 * @security Use for password-based key derivation only
 */
NEXTSSL_BASE_API int nextssl_base_core_argon2id_derive(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    uint8_t *derived_key, size_t derived_key_len);

/* ========== HMAC Operations ========== */

/**
 * HMAC-SHA256
 * 
 * @param key HMAC key
 * @param key_len Length of key (1-128 bytes typical)
 * @param data Data to authenticate
 * @param data_len Length of data
 * @param mac Output buffer for MAC (32 bytes)
 * @return 0 on success, negative on error
 * 
 * @validation Input parameters validated
 */
NEXTSSL_BASE_API int nextssl_base_core_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t mac[32]);

/**
 * HMAC-SHA512
 * 
 * @param key HMAC key
 * @param key_len Length of key (1-128 bytes typical)
 * @param data Data to authenticate
 * @param data_len Length of data
 * @param mac Output buffer for MAC (64 bytes)
 * @return 0 on success, negative on error
 * 
 * @validation Input parameters validated
 */
NEXTSSL_BASE_API int nextssl_base_core_hmac_sha512(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t mac[64]);

/* ========== Authenticated Encryption ========== */

/**
 * AES-256-GCM encryption (recommended AEAD)
 * 
 * @param key 256-bit key (32 bytes)
 * @param nonce Nonce (12 bytes recommended, MUST be unique per key)
 * @param nonce_len Length of nonce (8-16 bytes)
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len Length of AAD
 * @param plaintext Plaintext to encrypt
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output buffer for ciphertext (same length as plaintext)
 * @param tag Output buffer for authentication tag (16 bytes)
 * @return 0 on success, negative on error
 * 
 * @warning NEVER reuse nonce with same key - causes catastrophic failure
 * @validation All inputs validated, nonce uniqueness is caller's responsibility
 */
NEXTSSL_BASE_API int nextssl_base_core_aes256gcm_encrypt(
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
 * @param nonce Nonce used during encryption
 * @param nonce_len Length of nonce
 * @param aad Additional authenticated data (must match encryption)
 * @param aad_len Length of AAD
 * @param ciphertext Ciphertext to decrypt
 * @param ciphertext_len Length of ciphertext
 * @param tag Authentication tag from encryption (16 bytes)
 * @param plaintext Output buffer for plaintext (same length as ciphertext)
 * @return 1 if authenticated and decrypted, 0 if authentication failed, negative on error
 * 
 * @security Returns 0 if authentication fails - DO NOT use plaintext in this case
 */
NEXTSSL_BASE_API int nextssl_base_core_aes256gcm_decrypt(
    const uint8_t key[32],
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t tag[16],
    uint8_t *plaintext);

/**
 * ChaCha20-Poly1305 encryption (recommended for software-only)
 * 
 * @param key 256-bit key (32 bytes)
 * @param nonce Nonce (12 bytes, MUST be unique per key)
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len Length of AAD
 * @param plaintext Plaintext to encrypt
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output buffer for ciphertext (same length as plaintext)
 * @param tag Output buffer for authentication tag (16 bytes)
 * @return 0 on success, negative on error
 * 
 * @warning NEVER reuse nonce with same key
 */
NEXTSSL_BASE_API int nextssl_base_core_chacha20poly1305_encrypt(
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
 * @param nonce Nonce used during encryption (12 bytes)
 * @param aad Additional authenticated data
 * @param aad_len Length of AAD
 * @param ciphertext Ciphertext to decrypt
 * @param ciphertext_len Length of ciphertext
 * @param tag Authentication tag from encryption (16 bytes)
 * @param plaintext Output buffer for plaintext
 * @return 1 if authenticated and decrypted, 0 if authentication failed, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_core_chacha20poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t tag[16],
    uint8_t *plaintext);

/* ========== Secure Buffer Operations ========== */

/**
 * Securely zero memory (compiler cannot optimize away)
 * 
 * @param buf Buffer to zero
 * @param len Length of buffer
 * 
 * @note Use after handling sensitive data (keys, passwords, etc.)
 */
NEXTSSL_BASE_API void nextssl_base_core_secure_zero(
    void *buf,
    size_t len);

/**
 * Constant-time memory comparison
 * 
 * @param a First buffer
 * @param b Second buffer
 * @param len Length to compare
 * @return 1 if equal, 0 if not equal
 * 
 * @security Timing does not leak information about where differences occur
 */
NEXTSSL_BASE_API int nextssl_base_core_constant_time_compare(
    const void *a,
    const void *b,
    size_t len);

/**
 * Self-test for base core operations
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_BASE_API int nextssl_base_core_selftest(void);

#endif /* NEXTSSL_BASE_CORE_H */
