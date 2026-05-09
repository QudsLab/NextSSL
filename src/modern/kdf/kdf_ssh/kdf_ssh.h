/* kdf_ssh.h — SSH Key Derivation (RFC 4253 §7.2)
 *
 * SSH derives encryption keys, IVs, and MAC keys from the shared secret K,
 * exchange hash H, and a session ID using iterated SHA hashing:
 *
 *   HASH(K || H || X || session_id)       [first block]
 *   HASH(K || H || output_so_far)         [subsequent blocks]
 *
 * Where X is one of: 'A'..'F' (one letter per key purpose)
 *
 * Reference: RFC 4253 §7.2
 */
#ifndef NEXTSSL_KDF_SSH_H
#define NEXTSSL_KDF_SSH_H

#include <stdint.h>
#include <stddef.h>

/* ssh_kdf — Derive SSH key material for a given purpose letter.
 *
 * K          : shared secret (big-endian MPINT encoding per RFC 4251)
 * K_len      : length of K
 * H          : exchange hash (SHA-256 = 32 bytes for diffie-hellman-group14-sha256)
 * H_len      : length of H
 * session_id : session identifier (usually same as first H)
 * sid_len    : length of session_id
 * purpose    : single byte: 'A' (IV c→s), 'B' (IV s→c), 'C' (key c→s),
 *              'D' (key s→c), 'E' (HMAC key c→s), 'F' (HMAC key s→c)
 * out        : output buffer
 * out_len    : desired output bytes
 * Returns 0 on success, -1 on error. */
int ssh_kdf(const uint8_t *K,          size_t K_len,
            const uint8_t *H,          size_t H_len,
            const uint8_t *session_id, size_t sid_len,
            uint8_t        purpose,
            uint8_t       *out,        size_t out_len);

#endif /* NEXTSSL_KDF_SSH_H */
