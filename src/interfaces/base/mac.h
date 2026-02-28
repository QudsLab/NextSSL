/**
 * @file mac.h
 * @brief Layer 2: Message authentication code aggregation
 * @layer base
 * @category mac
 * @visibility semi-public
 * 
 * Message authentication for verifying data integrity and authenticity.
 * 
 * **Algorithms provided:**
 * - HMAC-SHA256 (recommended)
 * - HMAC-SHA512 (high security)
 * - HMAC-SHA3-256 (quantum-resistant)
 * 
 * @note For authenticated encryption, use core.h AEAD functions
 */

#ifndef NEXTSSL_BASE_MAC_H
#define NEXTSSL_BASE_MAC_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* ========== HMAC-SHA256 (RECOMMENDED) ========== */

/**
 * HMAC-SHA256 (recommended general-purpose MAC)
 * 
 * @param key MAC key
 * @param key_len Length of key (16-64 bytes typical)
 * @param data Data to authenticate
 * @param data_len Length of data
 * @param mac Output buffer for MAC tag (32 bytes)
 * @return 0 on success, negative on error
 * 
 * @compliance RFC 2104
 */
NEXTSSL_BASE_API int nextssl_base_mac_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t mac[32]);

/**
 * Verify HMAC-SHA256 (constant-time)
 * 
 * @param key MAC key
 * @param key_len Length of key
 * @param data Data to verify
 * @param data_len Length of data
 * @param expected_mac Expected MAC tag
 * @return 1 if valid, 0 if invalid, negative on error
 * 
 * @security Constant-time comparison
 */
NEXTSSL_BASE_API int nextssl_base_mac_hmac_sha256_verify(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    const uint8_t expected_mac[32]);

/* ========== HMAC-SHA512 (High security) ========== */

/**
 * HMAC-SHA512
 * 
 * @param key MAC key
 * @param key_len Length of key
 * @param data Data to authenticate
 * @param data_len Length of data
 * @param mac Output buffer for MAC tag (64 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_mac_hmac_sha512(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t mac[64]);

/**
 * Verify HMAC-SHA512 (constant-time)
 * 
 * @param key MAC key
 * @param key_len Length of key
 * @param data Data to verify
 * @param data_len Length of data
 * @param expected_mac Expected MAC tag
 * @return 1 if valid, 0 if invalid, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_mac_hmac_sha512_verify(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    const uint8_t expected_mac[64]);

/* ========== HMAC-SHA3-256 (Quantum-resistant) ========== */

/**
 * HMAC-SHA3-256 (quantum-resistant MAC)
 * 
 * @param key MAC key
 * @param key_len Length of key
 * @param data Data to authenticate
 * @param data_len Length of data
 * @param mac Output buffer for MAC tag (32 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_mac_hmac_sha3_256(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t mac[32]);

/**
 * Verify HMAC-SHA3-256 (constant-time)
 * 
 * @param key MAC key
 * @param key_len Length of key
 * @param data Data to verify
 * @param data_len Length of data
 * @param expected_mac Expected MAC tag
 * @return 1 if valid, 0 if invalid, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_mac_hmac_sha3_256_verify(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    const uint8_t expected_mac[32]);

/**
 * Self-test for MAC operations
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_BASE_API int nextssl_base_mac_selftest(void);

#endif /* NEXTSSL_BASE_MAC_H */
