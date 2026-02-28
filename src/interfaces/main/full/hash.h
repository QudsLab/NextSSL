/**
 * @file hash.h
 * @brief Layer 3: High-level cryptographic hashing
 * @layer main
 * @category hash
 * @visibility public
 * 
 * Simple hash function interface with secure defaults.
 * 
 * **Default algorithm:** SHA-256 (FIPS 180-4 compliant)
 * 
 * @security Modern, collision-resistant hash functions only
 * @note For legacy algorithms, use Layer 2 interfaces
 */

#ifndef NEXTSSL_MAIN_HASH_H
#define NEXTSSL_MAIN_HASH_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/**
 * Hash data (SHA-256 default)
 * 
 * @param data Data to hash
 * @param data_len Length of data
 * @param hash Output buffer (32 bytes)
 * @return 0 on success, negative on error
 * 
 * @example Hash file contents, compute checksums
 */
NEXTSSL_MAIN_API int nextssl_hash(
    const uint8_t *data, size_t data_len,
    uint8_t hash[32]);

/**
 * Hash data with SHA-512 (high security)
 * 
 * @param data Data to hash
 * @param data_len Length of data
 * @param hash Output buffer (64 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_MAIN_API int nextssl_hash_512(
    const uint8_t *data, size_t data_len,
    uint8_t hash[64]);

/**
 * Hash data with SHA3-256 (quantum-resistant)
 * 
 * @param data Data to hash
 * @param data_len Length of data
 * @param hash Output buffer (32 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_MAIN_API int nextssl_hash_sha3(
    const uint8_t *data, size_t data_len,
    uint8_t hash[32]);

/**
 * Fast cryptographic hash (BLAKE3)
 * 
 * @param data Data to hash
 * @param data_len Length of data
 * @param hash Output buffer (32 bytes)
 * @return 0 on success, negative on error
 * 
 * @note Faster than SHA-256, especially for large data
 */
NEXTSSL_MAIN_API int nextssl_hash_fast(
    const uint8_t *data, size_t data_len,
    uint8_t hash[32]);

#endif /* NEXTSSL_MAIN_HASH_H */
