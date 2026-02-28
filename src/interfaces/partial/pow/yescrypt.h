/**
 * @file yescrypt.h
 * @brief Layer 1 (Partial) - yescrypt Password Hashing Interface
 * @visibility HIDDEN (NEXTSSL_PARTIAL_API)
 * @layer 1
 * @category pow
 * @subcategory yescrypt
 * Thread safety: Thread-safe.
 */

#ifndef NEXTSSL_PARTIAL_POW_YESCRYPT_H
#define NEXTSSL_PARTIAL_POW_YESCRYPT_H

#include <stddef.h>
#include <stdint.h>
#include "../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

NEXTSSL_PARTIAL_API int
nextssl_partial_pow_yescrypt(
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    uint64_t N,
    uint32_t r,
    uint32_t p,
    uint8_t *output,
    size_t output_len
);

NEXTSSL_PARTIAL_API int
nextssl_partial_pow_yescrypt_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_POW_YESCRYPT_H */