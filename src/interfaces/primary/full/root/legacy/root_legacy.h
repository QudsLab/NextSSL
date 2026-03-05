/**
 * @file root/legacy/root_legacy.h
 * @brief NextSSL Root â€” Legacy algorithm interface.
 *
 * Split into two categories:
 *
 *   ALIVE  â€” Weak for security but still used (checksums, compatibility,
 *             protocol requirements). Not recommended for new security code.
 *
 *   UNSAFE â€” Cryptographically broken; included only for interoperability
 *             with legacy systems. MUST NOT be used for any security purpose.
 *
 * Naming: nextssl_root_legacy_{alive|unsafe}_<algorithm>(...)
 */

#ifndef NEXTSSL_ROOT_LEGACY_H
#define NEXTSSL_ROOT_LEGACY_H

#include <stddef.h>
#include <stdint.h>
#include "../../../../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * ALIVE â€” Weak but not fully broken for all uses
 * ============================================================== */

/** SHA-1: 20-byte output. */
NEXTSSL_API int nextssl_root_legacy_alive_sha1(const uint8_t *data, size_t len,
                                                uint8_t out[20]);

/** MD5: 16-byte output. */
NEXTSSL_API int nextssl_root_legacy_alive_md5(const uint8_t *data, size_t len,
                                               uint8_t out[16]);

/** RIPEMD-160: 20-byte output. */
NEXTSSL_API int nextssl_root_legacy_alive_ripemd160(const uint8_t *data, size_t len,
                                                     uint8_t out[20]);

/** Whirlpool: 64-byte output. */
NEXTSSL_API int nextssl_root_legacy_alive_whirlpool(const uint8_t *data, size_t len,
                                                     uint8_t out[64]);

/**
 * NT Hash (Windows NTLM): 16-byte output.
 * Computes MD4 over the UTF-16LE encoded Unicode password.
 * password is a null-terminated C string; it is converted internally.
 */
NEXTSSL_API int nextssl_root_legacy_alive_nthash(const char *password,
                                                  uint8_t out[16]);

/**
 * AES-128/192/256-ECB: no IV, no authentication.
 * Dangerous â€” only for legacy protocol compatibility.
 * pt_len / ct_len must be a multiple of 16.
 * key_len must be 16, 24, or 32 bytes.
 */
NEXTSSL_API int nextssl_root_legacy_alive_aesecb_encrypt(const uint8_t *key, size_t key_len,
                                                          const uint8_t *pt, size_t pt_len,
                                                          uint8_t *ct);

NEXTSSL_API int nextssl_root_legacy_alive_aesecb_decrypt(const uint8_t *key, size_t key_len,
                                                          const uint8_t *ct, size_t ct_len,
                                                          uint8_t *pt);

/* ================================================================
 * UNSAFE â€” Cryptographically broken
 * ============================================================== */

/** SHA-0: 20-byte output. Withdrawn before publication of SHA-1. */
NEXTSSL_API int nextssl_root_legacy_unsafe_sha0(const uint8_t *data, size_t len,
                                                 uint8_t out[20]);

/** MD2: 16-byte output. Fully broken. */
NEXTSSL_API int nextssl_root_legacy_unsafe_md2(const uint8_t *data, size_t len,
                                                uint8_t out[16]);

/** MD4: 16-byte output. Fully broken. */
NEXTSSL_API int nextssl_root_legacy_unsafe_md4(const uint8_t *data, size_t len,
                                                uint8_t out[16]);

/** HAS-160 (Korean standard): 20-byte output. Weak. */
NEXTSSL_API int nextssl_root_legacy_unsafe_has160(const uint8_t *data, size_t len,
                                                   uint8_t out[20]);

/** RIPEMD-128: 16-byte output. Weak â€” use RIPEMD-160 instead. */
NEXTSSL_API int nextssl_root_legacy_unsafe_ripemd128(const uint8_t *data, size_t len,
                                                      uint8_t out[16]);

/** RIPEMD-256: 32-byte output. Not well-reviewed; avoid. */
NEXTSSL_API int nextssl_root_legacy_unsafe_ripemd256(const uint8_t *data, size_t len,
                                                      uint8_t out[32]);

/** RIPEMD-320: 40-byte output. Not well-reviewed; avoid. */
NEXTSSL_API int nextssl_root_legacy_unsafe_ripemd320(const uint8_t *data, size_t len,
                                                      uint8_t out[40]);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_ROOT_LEGACY_H */
