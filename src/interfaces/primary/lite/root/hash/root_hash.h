/**
 * @file root/hash/root_hash.h (Lite)
 * @brief NextSSL Root Lite -- Explicit hash interface.
 *
 * Naming: nextssl_root_hash_<algorithm>(...)
 * All one-shot. Lite build provides: SHA-256, SHA-512, BLAKE3, Argon2id.
 *
 * @version 0.0.1-beta
 */

#ifndef NEXTSSL_LITE_ROOT_HASH_H
#define NEXTSSL_LITE_ROOT_HASH_H

#include <stddef.h>
#include <stdint.h>
#include "../../../../../config.h"  /* NEXTSSL_API */

#ifdef __cplusplus
extern "C" {
#endif

/** SHA-256: 32-byte output. */
NEXTSSL_API int nextssl_root_hash_sha256(const uint8_t *data, size_t len,
                                          uint8_t out[32]);

/** SHA-512: 64-byte output. */
NEXTSSL_API int nextssl_root_hash_sha512(const uint8_t *data, size_t len,
                                          uint8_t out[64]);

/**
 * BLAKE3: variable output.
 * @param out_len  Desired output length in bytes (32 is standard).
 */
NEXTSSL_API int nextssl_root_hash_blake3(const uint8_t *data, size_t len,
                                          uint8_t *out, size_t out_len);

/**
 * Argon2id KDF -- explicit params, caller supplies salt.
 *
 * @param pw        Password bytes
 * @param pw_len    Password length
 * @param salt      Salt bytes (min 16 bytes recommended)
 * @param salt_len  Salt length
 * @param t_cost    Time cost (iterations); use 3 for default
 * @param m_cost    Memory in KiB; use 65536 (64 MB) for default
 * @param par       Parallelism; use 4 for default
 * @param out       Output buffer
 * @param out_len   Desired output length (e.g. 32 bytes)
 * @return 0 on success, <0 on error
 */
NEXTSSL_API int nextssl_root_hash_argon2id(const uint8_t *pw, size_t pw_len,
                                            const uint8_t *salt, size_t salt_len,
                                            uint32_t t_cost, uint32_t m_cost,
                                            uint32_t par,
                                            uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_LITE_ROOT_HASH_H */
