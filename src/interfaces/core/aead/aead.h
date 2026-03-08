/* Task 105 merged header. Primitive layer + Aggregate layer. */
#ifndef NEXTSSL_CORE_AEAD_H
#define NEXTSSL_CORE_AEAD_H

/* =================== Primitive Layer =================== */
/**
 * @file aead.h
 * @brief Layer 1 (Partial) - AEAD Primitive Interface
 * 
 * SECURITY CLASSIFICATION: HIDDEN (NEXTSSL_CORE_API)
 * 
 * This interface provides granular access to AEAD (Authenticated Encryption
 * with Associated Data) primitives. It is NOT exposed to external users and
 * should only be accessed through Layer 2 (Base) aggregations.
 * 
 * VISIBILITY: Hidden from external symbols
 * NAMESPACE: nextssl_partial_core_aead_*
 * LAYER: 1 (Partial)
 * DEPENDENCIES: Layer 0 implementations only
 * 
 * THREAT MODEL:
 * - Prevents direct primitive misuse
 * - Enforces Layer 2 validation requirements
 * - No external symbol exposure
 * 
 * @version 1.0.0
 * @date 2026-02-28
 */

#ifndef NEXTSSL_CORE_AEAD_H_PRIMITIVE
#define NEXTSSL_CORE_AEAD_H_PRIMITIVE

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * VISIBILITY CONFIGURATION
 * ================================================================ */

/**
 * @brief Partial API visibility marker (hidden from external use)
 * 
 * Layer 1 symbols are NEVER exported. They are internal interfaces
 * used only by Layer 2 (Base) implementations.
 */
#ifndef NEXTSSL_CORE_API
    #if defined(_WIN32) || defined(__CYGWIN__)
        #define NEXTSSL_CORE_API
    #elif defined(__GNUC__) && __GNUC__ >= 4
        #define NEXTSSL_CORE_API __attribute__((visibility("hidden")))
    #else
        #define NEXTSSL_CORE_API
    #endif
#endif

/* ================================================================
 * ERROR CODES
 * ================================================================ */

#define NEXTSSL_AEAD_SUCCESS                0
#define NEXTSSL_AEAD_ERROR_NULL_POINTER    -1
#define NEXTSSL_AEAD_ERROR_INVALID_LENGTH  -2
#define NEXTSSL_AEAD_ERROR_BUFFER_TOO_SMALL -3
#define NEXTSSL_AEAD_ERROR_AUTH_FAILED     -4
#define NEXTSSL_AEAD_ERROR_INVALID_NONCE   -5

/* ================================================================
 * CONSTANTS
 * ================================================================ */

#define NEXTSSL_AES_256_GCM_KEY_SIZE     32
#define NEXTSSL_AES_256_GCM_NONCE_SIZE   12
#define NEXTSSL_AES_256_GCM_TAG_SIZE     16

#define NEXTSSL_CHACHA20_POLY1305_KEY_SIZE   32
#define NEXTSSL_CHACHA20_POLY1305_NONCE_SIZE 12
#define NEXTSSL_CHACHA20_POLY1305_TAG_SIZE   16

/* ================================================================
 * AES-256-GCM OPERATIONS
 * ================================================================ */

/**
 * @brief AES-256-GCM encryption (partial interface)
 * 
 * SECURITY NOTES:
 * - Nonce MUST be unique for each encryption with the same key
 * - Key MUST be 32 bytes (256 bits)
 * - Tag is appended to ciphertext
 * - Constant-time implementation
 * 
 * @param key Key material (32 bytes)
 * @param nonce Nonce (12 bytes, must be unique per key)
 * @param plaintext Plaintext data
 * @param plaintext_len Length of plaintext
 * @param aad Additional authenticated data (can be NULL if aad_len is 0)
 * @param aad_len Length of AAD
 * @param ciphertext Output buffer (must hold plaintext_len + 16 bytes)
 * @param ciphertext_len Output length (set to plaintext_len + 16)
 * @return NEXTSSL_AEAD_SUCCESS or error code
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 * @note Called by nextssl_base_aead_encrypt_aes_gcm()
 */
NEXTSSL_CORE_API int nextssl_partial_core_aead_aes_gcm_encrypt(
    const uint8_t key[NEXTSSL_AES_256_GCM_KEY_SIZE],
    const uint8_t nonce[NEXTSSL_AES_256_GCM_NONCE_SIZE],
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *ciphertext,
    size_t *ciphertext_len
);

/**
 * @brief AES-256-GCM decryption (partial interface)
 * 
 * SECURITY NOTES:
 * - Authentication tag MUST be verified before using plaintext
 * - Returns error if authentication fails
 * - Constant-time tag comparison
 * 
 * @param key Key material (32 bytes)
 * @param nonce Nonce (12 bytes)
 * @param ciphertext Ciphertext with appended tag
 * @param ciphertext_len Length of ciphertext (includes 16-byte tag)
 * @param aad Additional authenticated data (must match encryption)
 * @param aad_len Length of AAD
 * @param plaintext Output buffer (must hold ciphertext_len - 16 bytes)
 * @param plaintext_len Output length (set to ciphertext_len - 16)
 * @return NEXTSSL_AEAD_SUCCESS or error code
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 * @note Called by nextssl_base_aead_decrypt_aes_gcm()
 */
NEXTSSL_CORE_API int nextssl_partial_core_aead_aes_gcm_decrypt(
    const uint8_t key[NEXTSSL_AES_256_GCM_KEY_SIZE],
    const uint8_t nonce[NEXTSSL_AES_256_GCM_NONCE_SIZE],
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *plaintext,
    size_t *plaintext_len
);

/* ================================================================
 * CHACHA20-POLY1305 OPERATIONS
 * ================================================================ */

/**
 * @brief ChaCha20-Poly1305 encryption (partial interface)
 * 
 * SECURITY NOTES:
 * - Faster than AES-GCM on platforms without AES-NI
 * - Nonce MUST be unique for each encryption with the same key
 * - Constant-time implementation
 * 
 * @param key Key material (32 bytes)
 * @param nonce Nonce (12 bytes, must be unique per key)
 * @param plaintext Plaintext data
 * @param plaintext_len Length of plaintext
 * @param aad Additional authenticated data (can be NULL if aad_len is 0)
 * @param aad_len Length of AAD
 * @param ciphertext Output buffer (must hold plaintext_len + 16 bytes)
 * @param ciphertext_len Output length (set to plaintext_len + 16)
 * @return NEXTSSL_AEAD_SUCCESS or error code
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 * @note Called by nextssl_base_aead_encrypt_chacha20_poly1305()
 */
NEXTSSL_CORE_API int nextssl_partial_core_aead_chacha20_poly1305_encrypt(
    const uint8_t key[NEXTSSL_CHACHA20_POLY1305_KEY_SIZE],
    const uint8_t nonce[NEXTSSL_CHACHA20_POLY1305_NONCE_SIZE],
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *ciphertext,
    size_t *ciphertext_len
);

/**
 * @brief ChaCha20-Poly1305 decryption (partial interface)
 * 
 * SECURITY NOTES:
 * - Authentication tag MUST be verified before using plaintext
 * - Returns error if authentication fails
 * - Constant-time tag comparison
 * 
 * @param key Key material (32 bytes)
 * @param nonce Nonce (12 bytes)
 * @param ciphertext Ciphertext with appended tag
 * @param ciphertext_len Length of ciphertext (includes 16-byte tag)
 * @param aad Additional authenticated data (must match encryption)
 * @param aad_len Length of AAD
 * @param plaintext Output buffer (must hold ciphertext_len - 16 bytes)
 * @param plaintext_len Output length (set to ciphertext_len - 16)
 * @return NEXTSSL_AEAD_SUCCESS or error code
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 * @note Called by nextssl_base_aead_decrypt_chacha20_poly1305()
 */
NEXTSSL_CORE_API int nextssl_partial_core_aead_chacha20_poly1305_decrypt(
    const uint8_t key[NEXTSSL_CHACHA20_POLY1305_KEY_SIZE],
    const uint8_t nonce[NEXTSSL_CHACHA20_POLY1305_NONCE_SIZE],
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *plaintext,
    size_t *plaintext_len
);

/* ================================================================
 * ADDITIONAL AEAD ALGORITHMS
 * ================================================================ */

/**
 * @brief AES-256-GCM-SIV encryption (partial interface)
 * 
 * SECURITY NOTES:
 * - Nonce-misuse resistant (safer if nonce reuse occurs)
 * - Slightly slower than AES-GCM
 * - Deterministic with same key+nonce+plaintext
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 */
NEXTSSL_CORE_API int nextssl_partial_core_aead_aes_gcm_siv_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *ciphertext,
    size_t *ciphertext_len
);

/**
 * @brief AES-256-GCM-SIV decryption (partial interface)
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 */
NEXTSSL_CORE_API int nextssl_partial_core_aead_aes_gcm_siv_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *plaintext,
    size_t *plaintext_len
);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_CORE_AEAD_H_PRIMITIVE */

/**
 * SECURITY AUDIT NOTES:
 * 
 * 1. Symbol Visibility:
 *    - All functions marked NEXTSSL_CORE_API (hidden)
 *    - No external symbol exposure
 *    - Verified by scripts/check_symbols.sh
 * 
 * 2. Namespace Convention:
 *    - All symbols: nextssl_partial_core_aead_*
 *    - No collisions with other layers
 * 
 * 3. Layer Boundaries:
 *    - Depends only on Layer 0 (implementation)
 *    - Called only by Layer 2 (Base)
 *    - No direct user access
 * 
 * 4. Threat Mitigation:
 *    - Prevents direct AEAD misuse
 *    - Enforces MUST pass through Layer 2 validation
 *    - Nonce uniqueness documented but not enforced (Layer 2 responsibility)
 * 
 * 5. Constant-Time Requirements:
 *    - Tag comparison MUST be constant-time (Layer 0 implementation)
 *    - No secret-dependent branching
 *    - Verified by tools/verify_constant_time.sh
 * 
 * NEXT REVIEW: When Layer 2 (Base) implementation completed
 */

/* =================== Aggregate Layer =================== */
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

#ifndef NEXTSSL_CORE_AEAD_H_AGGREGATE
#define NEXTSSL_CORE_AEAD_H_AGGREGATE

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
NEXTSSL_CORE_API int nextssl_base_aead_aes256gcm_encrypt(
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
NEXTSSL_CORE_API int nextssl_base_aead_aes256gcm_decrypt(
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
NEXTSSL_CORE_API int nextssl_base_aead_chacha20poly1305_encrypt(
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
NEXTSSL_CORE_API int nextssl_base_aead_chacha20poly1305_decrypt(
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
NEXTSSL_CORE_API int nextssl_base_aead_aes256gcmsiv_encrypt(
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
NEXTSSL_CORE_API int nextssl_base_aead_aes256gcmsiv_decrypt(
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
NEXTSSL_CORE_API int nextssl_base_aead_modern_selftest(void);

#endif /* NEXTSSL_CORE_AEAD_H_AGGREGATE */

#endif /* NEXTSSL_CORE_AEAD_H */
