/* hkdf.h — HKDF over hash_ops_t vtable (RFC 5869, Plan 202)
 *
 * Provides vtable-generic HKDF-Extract, HKDF-Expand, and the combined
 * hkdf_ex() entry-point.  Also provides an RFC 8446 Expand-Label variant.
 *
 * These functions accept any hash_ops_t (sha256, sha512, blake3, etc.).
 * NULL hash defaults to sha256_ops via hash_registry_init().
 */
#ifndef MODERN_HKDF_H
#define MODERN_HKDF_H

#include <stddef.h>
#include <stdint.h>
#include "../../hash/interface/hash_ops.h"

/* -------------------------------------------------------------------------
 * hkdf_extract_ex — RFC 5869 §2.2 Extract
 *
 * PRK = HMAC-Hash(salt, IKM)
 * salt = NULL → all-zero salt of hash->digest_size bytes (RFC 5869 §2.2)
 *
 * prk must point to a buffer of at least hash->digest_size bytes.
 * Returns 0 on success, -1 on invalid arguments.
 * -------------------------------------------------------------------------*/
int hkdf_extract_ex(const hash_ops_t *hash,
                    const uint8_t    *salt,    size_t salt_len,
                    const uint8_t    *ikm,     size_t ikm_len,
                    uint8_t          *prk);

/* -------------------------------------------------------------------------
 * hkdf_expand_ex — RFC 5869 §2.3 Expand
 *
 * OKM = T(1) ‖ T(2) ‖ … truncated to okm_len bytes
 * Ceiling: okm_len ≤ 255 × hash->digest_size
 *
 * Returns 0 on success, -1 on invalid arguments or ceiling exceeded.
 * -------------------------------------------------------------------------*/
int hkdf_expand_ex(const hash_ops_t *hash,
                   const uint8_t    *prk,      size_t prk_len,
                   const uint8_t    *info,     size_t info_len,
                   uint8_t          *okm,      size_t okm_len);

/* -------------------------------------------------------------------------
 * hkdf_ex — combined Extract + Expand
 *
 * hash = NULL → defaults to sha256_ops (backward-compatible).
 * Returns 0 on success, -1 on error.
 * -------------------------------------------------------------------------*/
int hkdf_ex(const hash_ops_t *hash,
            const uint8_t    *salt,    size_t salt_len,
            const uint8_t    *ikm,     size_t ikm_len,
            const uint8_t    *info,    size_t info_len,
            uint8_t          *okm,     size_t okm_len);

/* -------------------------------------------------------------------------
 * hkdf_expand_label_ex — RFC 8446 §7.1 HKDF-Expand-Label
 *
 * HKDF-Expand-Label(Secret, Label, Context, Length)
 *   HkdfLabel = Length ‖ "tls13 " ‖ label ‖ Context_len ‖ Context
 *
 * Returns 0 on success, -1 on error.
 * -------------------------------------------------------------------------*/
int hkdf_expand_label_ex(const hash_ops_t *hash,
                         const uint8_t    *secret,      size_t  secret_len,
                         const char       *label,
                         const uint8_t    *context,     size_t  context_len,
                         uint8_t          *okm,         size_t  okm_len);

#endif /* MODERN_HKDF_H */
