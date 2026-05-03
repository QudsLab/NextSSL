/* pbkdf2.h — PBKDF2 over hash_ops_t vtable (RFC 2898, Plan 202)
 *
 * Derives key material from a password and salt using PBKDF2 with HMAC
 * backed by any registered hash algorithm.
 */
#ifndef MODERN_PBKDF2_H
#define MODERN_PBKDF2_H

#include <stddef.h>
#include <stdint.h>
#include "../../../hash/interface/hash_ops.h"

/* -------------------------------------------------------------------------
 * pbkdf2_ex — RFC 2898 §5.2 PBKDF2-HMAC-<Hash>
 *
 * hash       — hash vtable (e.g. &sha256_ops, &sha512_ops); NULL → sha256
 * password   — password bytes
 * pwdlen     — password length
 * salt       — salt bytes
 * saltlen    — salt length (recommended ≥ 16 bytes)
 * iterations — iteration count (recommended ≥ 100,000 for SHA-256)
 * out        — derived key output buffer
 * outlen     — desired derived key length in bytes
 *
 * Ceiling: outlen ≤ (2^32 - 1) × hash->digest_size
 *
 * Memory discipline (Plan 204):
 *   Per-block HMAC state (U_i buffers) are wiped before returning.
 *
 * Returns 0 on success, -1 on invalid arguments.
 * -------------------------------------------------------------------------*/
int pbkdf2_ex(const hash_ops_t *hash,
              const uint8_t    *password, size_t pwdlen,
              const uint8_t    *salt,     size_t saltlen,
              uint32_t          iterations,
              uint8_t          *out,      size_t outlen);

/* -------------------------------------------------------------------------
 * pbkdf2_ex_adapter — PBKDF2 using a hash_adapter_t as the HMAC PRF
 *
 * ha         — pre-configured hash adapter (any plain or KDF adapter)
 * password   — password bytes
 * pwdlen     — password length
 * salt       — salt bytes
 * saltlen    — salt length (recommended ≥ 16 bytes)
 * iterations — iteration count
 * out        — derived key output buffer
 * outlen     — desired derived key length in bytes
 *
 * Returns 0 on success, -1 on invalid arguments or internal error.
 * -------------------------------------------------------------------------*/
#include "../../../hash/adapters/hash_adapter.h"
int pbkdf2_ex_adapter(const hash_adapter_t *ha,
                      const uint8_t *password, size_t pwdlen,
                      const uint8_t *salt,     size_t saltlen,
                      uint32_t       iterations,
                      uint8_t       *out,       size_t outlen);

#endif /* MODERN_PBKDF2_H */
