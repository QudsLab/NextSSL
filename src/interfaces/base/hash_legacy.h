/**
 * @file hash_legacy.h
 * @brief Layer 2: Legacy hash function aggregation
 * @layer base
 * @category hash
 * @visibility semi-public
 * 
 * Legacy hash functions provided ONLY for compatibility with existing systems.
 * 
 * ⚠️  **SECURITY WARNING** ⚠️
 * These algorithms are DEPRECATED due to known vulnerabilities:
 * - SHA-1: Collision attacks practical (2017)
 * - MD5: Completely broken, trivial collisions
 * 
 * **DO NOT USE for new applications**
 * Use hash.h interfaces (SHA-256, SHA3-256, BLAKE2b) instead.
 * 
 * @security For compatibility ONLY - these functions log warnings
 */

#ifndef NEXTSSL_BASE_HASH_LEGACY_H
#define NEXTSSL_BASE_HASH_LEGACY_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* ========== SHA-1 (DEPRECATED) ========== */

/**
 * SHA-1 (DEPRECATED - collision attacks practical)
 * 
 * @param data Input data
 * @param len Length of data
 * @param hash Output buffer (20 bytes)
 * @return 0 on success, negative on error
 * 
 * @deprecated Use SHA-256 or SHA3-256 instead
 * @warning Collision resistant? NO - SHAttered attack (2017)
 * @use_case Legacy protocol compatibility ONLY (Git, older TLS)
 */
NEXTSSL_BASE_API int nextssl_base_hash_legacy_sha1(
    const uint8_t *data, size_t len,
    uint8_t hash[20]) __attribute__((deprecated));

/* ========== MD5 (BROKEN) ========== */

/**
 * MD5 (BROKEN - DO NOT USE)
 * 
 * @param data Input data
 * @param len Length of data
 * @param hash Output buffer (16 bytes)
 * @return 0 on success, negative on error
 * 
 * @deprecated Use SHA-256 or SHA3-256 instead
 * @warning Completely broken - trivial collision attacks
 * @use_case Non-cryptographic checksums ONLY
 * @note This function logs a security warning when called
 */
NEXTSSL_BASE_API int nextssl_base_hash_legacy_md5(
    const uint8_t *data, size_t len,
    uint8_t hash[16]) __attribute__((deprecated));

/* ========== SHA-224 (Truncated SHA-256) ========== */

/**
 * SHA-224 (truncated SHA-256, rarely needed)
 * 
 * @param data Input data
 * @param len Length of data
 * @param hash Output buffer (28 bytes)
 * @return 0 on success, negative on error
 * 
 * @note Prefer SHA-256 unless protocol requires SHA-224 specifically
 * @compliance FIPS 180-4
 * @security Secure but less common - use SHA-256 for broader compatibility
 */
NEXTSSL_BASE_API int nextssl_base_hash_legacy_sha224(
    const uint8_t *data, size_t len,
    uint8_t hash[28]);

/* ========== SHA-384 (Truncated SHA-512) ========== */

/**
 * SHA-384 (truncated SHA-512, rarely needed)
 * 
 * @param data Input data
 * @param len Length of data
 * @param hash Output buffer (48 bytes)
 * @return 0 on success, negative on error
 * 
 * @note Prefer SHA-512 unless protocol requires SHA-384 specifically
 * @compliance FIPS 180-4
 * @security Secure but less common - use SHA-512 for broader compatibility
 */
NEXTSSL_BASE_API int nextssl_base_hash_legacy_sha384(
    const uint8_t *data, size_t len,
    uint8_t hash[48]);

/**
 * Self-test for legacy hash operations
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_BASE_API int nextssl_base_hash_legacy_selftest(void);

#endif /* NEXTSSL_BASE_HASH_LEGACY_H */
