/**
 * @file hash.h
 * @brief Layer 2: Cryptographic hash function aggregation
 * @layer base
 * @category hash
 * @visibility semi-public
 * 
 * Modern, recommended hash functions with input validation and safe defaults.
 * 
 * **Algorithms provided:**
 * - SHA-2 (SHA-256, SHA-512) - FIPS 180-4, widely deployed
 * - SHA-3 (SHA3-256, SHA3-512) - FIPS 202, quantum-resistant
 * - BLAKE2b - Fast, secure alternative to SHA-2
 * - BLAKE3 - Latest generation, highly parallelizable
 * 
 * @note For legacy algorithms (SHA-1, MD5), see hash_legacy.h
 */

#ifndef NEXTSSL_BASE_HASH_H
#define NEXTSSL_BASE_HASH_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* ========== SHA-2 Family ========== */

/**
 * SHA-256 (recommended for general use)
 * 
 * @param data Input data
 * @param len Length of data
 * @param hash Output buffer (32 bytes)
 * @return 0 on success, negative on error
 * 
 * @compliance FIPS 180-4
 * @validation Input validated
 */
NEXTSSL_BASE_API int nextssl_base_hash_sha256(
    const uint8_t *data, size_t len,
    uint8_t hash[32]);

/**
 * SHA-512 (for high-security applications)
 * 
 * @param data Input data
 * @param len Length of data
 * @param hash Output buffer (64 bytes)
 * @return 0 on success, negative on error
 * 
 * @compliance FIPS 180-4
 */
NEXTSSL_BASE_API int nextssl_base_hash_sha512(
    const uint8_t *data, size_t len,
    uint8_t hash[64]);

/* ========== SHA-3 Family ========== */

/**
 * SHA3-256 (quantum-resistant hash)
 * 
 * @param data Input data
 * @param len Length of data
 * @param hash Output buffer (32 bytes)
 * @return 0 on success, negative on error
 * 
 * @compliance FIPS 202
 * @security Quantum-resistant
 */
NEXTSSL_BASE_API int nextssl_base_hash_sha3_256(
    const uint8_t *data, size_t len,
    uint8_t hash[32]);

/**
 * SHA3-512 (quantum-resistant, high security)
 * 
 * @param data Input data
 * @param len Length of data
 * @param hash Output buffer (64 bytes)
 * @return 0 on success, negative on error
 * 
 * @compliance FIPS 202
 */
NEXTSSL_BASE_API int nextssl_base_hash_sha3_512(
    const uint8_t *data, size_t len,
    uint8_t hash[64]);

/* ========== BLAKE2 ========== */

/**
 * BLAKE2b (fast, secure, 64-bit optimized)
 * 
 * @param data Input data
 * @param len Length of data
 * @param hash Output buffer (64 bytes for full output)
 * @param hash_len Desired output length (1-64 bytes)
 * @return 0 on success, negative on error
 * 
 * @compliance RFC 7693
 * @note Faster than SHA-2/3 on 64-bit platforms
 */
NEXTSSL_BASE_API int nextssl_base_hash_blake2b(
    const uint8_t *data, size_t len,
    uint8_t *hash, size_t hash_len);

/* ========== BLAKE3 ========== */

/**
 * BLAKE3 (fastest modern hash, parallelizable)
 * 
 * @param data Input data
 * @param len Length of data
 * @param hash Output buffer (32 bytes default)
 * @return 0 on success, negative on error
 * 
 * @note Significantly faster than predecessors, especially for large inputs
 */
NEXTSSL_BASE_API int nextssl_base_hash_blake3(
    const uint8_t *data, size_t len,
    uint8_t hash[32]);

/**
 * Self-test for hash operations
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_BASE_API int nextssl_base_hash_selftest(void);

#endif /* NEXTSSL_BASE_HASH_H */
