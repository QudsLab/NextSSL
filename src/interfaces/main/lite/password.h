/**
 * @file password_lite.h
 * @brief Lite variant password hashing API (HKDF, Argon2id only)
 * @version 0.1.0-beta-lite
 * @date 2026-02-28
 */

#ifndef NEXTSSL_MAIN_LITE_PASSWORD_H
#define NEXTSSL_MAIN_LITE_PASSWORD_H

#include "../../../config.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Password/KDF algorithms available in lite variant
 */
typedef enum {
    NEXTSSL_LITE_KDF_HKDF,      /**< HKDF-SHA256 (RFC 5869) */
    NEXTSSL_LITE_KDF_ARGON2ID   /**< Argon2id (RFC 9106) */
} nextssl_lite_kdf_algorithm_t;

/**
 * @brief Hash password with Argon2id
 * 
 * Uses Argon2id with recommended parameters:
 * - Memory: 64 MB
 * - Iterations: 3
 * - Parallelism: 4
 * 
 * @param password Password bytes
 * @param password_len Password length
 * @param salt Salt bytes (16 bytes recommended)
 * @param salt_len Salt length
 * @param output Output buffer (32 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_API int nextssl_lite_password_hash(
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    uint8_t *output
);

/**
 * @brief Hash password with custom parameters
 * 
 * @param password Password bytes
 * @param password_len Password length
 * @param salt Salt bytes
 * @param salt_len Salt length
 * @param memory_kb Memory cost in KB (e.g., 65536 = 64MB)
 * @param iterations Time cost (iterations)
 * @param parallelism Parallelism degree
 * @param output Output buffer (32 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_API int nextssl_lite_password_hash_ex(
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    uint32_t memory_kb,
    uint32_t iterations,
    uint32_t parallelism,
    uint8_t *output
);

/**
 * @brief Verify password against hash
 * 
 * Constant-time comparison to prevent timing attacks
 * 
 * @param password Password to verify
 * @param password_len Password length
 * @param salt Salt used for hashing
 * @param salt_len Salt length
 * @param expected_hash Expected hash value
 * @return 0 if password matches, negative otherwise
 * 
 * @retval 0 Password matches
 * @retval -NEXTSSL_ERROR_AUTH_FAILED Password does not match
 */
NEXTSSL_API int nextssl_lite_password_verify(
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *expected_hash
);

/**
 * @brief Derive key using HKDF-SHA256
 * 
 * @param ikm Input key material
 * @param ikm_len IKM length
 * @param salt Salt (can be NULL)
 * @param salt_len Salt length
 * @param info Context/application info (can be NULL)
 * @param info_len Info length
 * @param output Output key material
 * @param output_len Desired output length (max 8160 bytes = 255 * 32)
 * @return 0 on success, negative on error
 */
NEXTSSL_API int nextssl_lite_kdf_derive(
    const uint8_t *ikm,
    size_t ikm_len,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *info,
    size_t info_len,
    uint8_t *output,
    size_t output_len
);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_MAIN_LITE_PASSWORD_H */
