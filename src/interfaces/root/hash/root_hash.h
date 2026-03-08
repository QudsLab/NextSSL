/**
 * @file root/hash/root_hash.h
 * @brief NextSSL Root — Explicit hash algorithm interface.
 *
 * Naming: nextssl_root_hash_<algorithm>(data, len, out [, out_len])
 * All one-shot; caller provides output buffer sized to the constant below.
 *
 * Argon2 variants live here (they are fundamentally hash/KDF algorithms).
 */

#ifndef NEXTSSL_ROOT_HASH_H
#define NEXTSSL_ROOT_HASH_H

#include <stddef.h>
#include <stdint.h>
#include "../../../config.h"  /* NEXTSSL_API */

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------
 * SHA-2 family
 * ------------------------------------------------------------------ */

#ifndef NEXTSSL_BUILD_LITE
/** SHA-224: 28-byte output. */
NEXTSSL_API int nextssl_root_hash_sha224(const uint8_t *data, size_t len,
                                         uint8_t out[28]);
#endif /* NEXTSSL_BUILD_LITE */

/** SHA-256: 32-byte output. */
NEXTSSL_API int nextssl_root_hash_sha256(const uint8_t *data, size_t len,
                                         uint8_t out[32]);

/** SHA-512: 64-byte output. */
NEXTSSL_API int nextssl_root_hash_sha512(const uint8_t *data, size_t len,
                                         uint8_t out[64]);

/* ------------------------------------------------------------------
 * BLAKE2 family
 * ------------------------------------------------------------------ */

#ifndef NEXTSSL_BUILD_LITE
/** BLAKE2b: variable output, 1–64 bytes. */
NEXTSSL_API int nextssl_root_hash_blake2b(const uint8_t *data, size_t len,
                                          uint8_t *out, size_t out_len);

/** BLAKE2s: variable output, 1–32 bytes. */
NEXTSSL_API int nextssl_root_hash_blake2s(const uint8_t *data, size_t len,
                                          uint8_t *out, size_t out_len);
#endif /* NEXTSSL_BUILD_LITE */

/** BLAKE3: variable output length. */
NEXTSSL_API int nextssl_root_hash_blake3(const uint8_t *data, size_t len,
                                         uint8_t *out, size_t out_len);

/* ------------------------------------------------------------------
 * SHA-3 / Keccak family
 * ------------------------------------------------------------------ */

#ifndef NEXTSSL_BUILD_LITE
/** SHA-3-224: 28-byte output. */
NEXTSSL_API int nextssl_root_hash_sha3_224(const uint8_t *data, size_t len,
                                            uint8_t out[28]);

/** SHA-3-256: 32-byte output. */
NEXTSSL_API int nextssl_root_hash_sha3_256(const uint8_t *data, size_t len,
                                            uint8_t out[32]);

/** SHA-3-384: 48-byte output. */
NEXTSSL_API int nextssl_root_hash_sha3_384(const uint8_t *data, size_t len,
                                            uint8_t out[48]);

/** SHA-3-512: 64-byte output. */
NEXTSSL_API int nextssl_root_hash_sha3_512(const uint8_t *data, size_t len,
                                            uint8_t out[64]);

/** Keccak-256 (pre-NIST, Ethereum variant): 32-byte output. */
NEXTSSL_API int nextssl_root_hash_keccak256(const uint8_t *data, size_t len,
                                             uint8_t out[32]);

/* ------------------------------------------------------------------
 * SHAKE (XOF)
 * ------------------------------------------------------------------ */

/** SHAKE-128: variable output. */
NEXTSSL_API int nextssl_root_hash_shake128(const uint8_t *data, size_t len,
                                           uint8_t *out, size_t out_len);

/** SHAKE-256: variable output. */
NEXTSSL_API int nextssl_root_hash_shake256(const uint8_t *data, size_t len,
                                           uint8_t *out, size_t out_len);
#endif /* NEXTSSL_BUILD_LITE */

/* ------------------------------------------------------------------
 * Argon2 (memory-hard KDF / password hash)
 *
 * Params: t_cost=iterations, m_cost=KiB, par=parallelism.
 * Caller provides salt.  Use nextssl_password_hash() for auto-salt.
 * ------------------------------------------------------------------ */

/** Argon2id (recommended): data-independent + data-dependent hybrid. */
NEXTSSL_API int nextssl_root_hash_argon2id(const uint8_t *pw, size_t pw_len,
                                            const uint8_t *salt, size_t salt_len,
                                            uint32_t t_cost, uint32_t m_cost,
                                            uint32_t par,
                                            uint8_t *out, size_t out_len);

#ifndef NEXTSSL_BUILD_LITE
/** Argon2d: data-dependent (GPU-resistant, side-channel risk in browser). */
NEXTSSL_API int nextssl_root_hash_argon2d(const uint8_t *pw, size_t pw_len,
                                           const uint8_t *salt, size_t salt_len,
                                           uint32_t t_cost, uint32_t m_cost,
                                           uint32_t par,
                                           uint8_t *out, size_t out_len);

/** Argon2i: data-independent (side-channel safe, less GPU-resistant). */
NEXTSSL_API int nextssl_root_hash_argon2i(const uint8_t *pw, size_t pw_len,
                                           const uint8_t *salt, size_t salt_len,
                                           uint32_t t_cost, uint32_t m_cost,
                                           uint32_t par,
                                           uint8_t *out, size_t out_len);
#endif /* NEXTSSL_BUILD_LITE */

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_ROOT_HASH_H */
