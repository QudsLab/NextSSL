/**
 * @file hash_lite.h
 * @brief Lite variant hash API (SHA-256, SHA-512, BLAKE3 only)
 * @version 0.1.0-beta-lite
 * @date 2026-02-28
 */

#ifndef NEXTSSL_MAIN_LITE_HASH_H
#define NEXTSSL_MAIN_LITE_HASH_H

#include "../../../config.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Hash algorithms available in lite variant
 */
typedef enum {
    NEXTSSL_LITE_HASH_SHA256,    /**< SHA-256 (32 bytes output) */
    NEXTSSL_LITE_HASH_SHA512,    /**< SHA-512 (64 bytes output) */
    NEXTSSL_LITE_HASH_BLAKE3      /**< BLAKE3 (32 bytes output, extensible) */
} nextssl_lite_hash_algorithm_t;

/**
 * @brief Compute hash (lite variant)
 * 
 * Supported algorithms:
 * - "SHA-256" (default) - FIPS 180-4
 * - "SHA-512" - FIPS 180-4
 * - "BLAKE3" - Modern, fast
 * 
 * @param algorithm Algorithm name (NULL defaults to SHA-256)
 * @param data Input data
 * @param data_len Input length (max 1GB)
 * @param output Output buffer (min 32 bytes for SHA-256/BLAKE3, 64 for SHA-512)
 * @return 0 on success, negative error code on failure
 * 
 * @retval 0 Success
 * @retval -NEXTSSL_ERROR_INVALID_ALGORITHM Algorithm not supported in lite variant
 * @retval -NEXTSSL_ERROR_INVALID_PARAMETER NULL pointer or invalid length
 * @retval -NEXTSSL_ERROR_BUFFER_TOO_SMALL Output buffer too small
 */
NEXTSSL_API int nextssl_lite_hash(
    const char *algorithm,
    const uint8_t *data,
    size_t data_len,
    uint8_t *output
);

/**
 * @brief Get hash output size
 * 
 * @param algorithm Algorithm name
 * @return Output size in bytes, or -1 if not supported
 * 
 * @retval 32 SHA-256 or BLAKE3
 * @retval 64 SHA-512
 * @retval -1 Algorithm not available in lite variant
 */
NEXTSSL_API int nextssl_lite_hash_size(const char *algorithm);

/**
 * @brief Incremental hashing: initialize context
 * 
 * @param algorithm Algorithm name
 * @param ctx Output context pointer (allocated internally)
 * @return 0 on success, negative on error
 */
NEXTSSL_API int nextssl_lite_hash_init(const char *algorithm, void **ctx);

/**
 * @brief Incremental hashing: update with data
 * 
 * @param ctx Context from nextssl_lite_hash_init()
 * @param data Input data
 * @param len Input length
 * @return 0 on success, negative on error
 */
NEXTSSL_API int nextssl_lite_hash_update(void *ctx, const uint8_t *data, size_t len);

/**
 * @brief Incremental hashing: finalize and get output
 * 
 * @param ctx Context pointer (will be freed)
 * @param output Output buffer
 * @return 0 on success, negative on error
 */
NEXTSSL_API int nextssl_lite_hash_final(void *ctx, uint8_t *output);

/**
 * @brief Check if hash algorithm is available
 * 
 * @param algorithm Algorithm name
 * @return 1 if available, 0 otherwise
 */
NEXTSSL_API int nextssl_lite_hash_available(const char *algorithm);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_MAIN_LITE_HASH_H */
