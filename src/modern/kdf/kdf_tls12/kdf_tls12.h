/* kdf_tls12.h — TLS 1.2 PRF (RFC 5246 §5)
 *
 * TLS 1.2 uses P_SHA256 or P_SHA384 as its PRF:
 *   PRF(secret, label, seed) = P_<hash>(secret, label + seed)
 *   P_hash(secret, seed) = HMAC(secret, A(1)||seed) ||
 *                           HMAC(secret, A(2)||seed) || ...
 *   A(0) = seed; A(i) = HMAC(secret, A(i-1))
 *
 * The TLS 1.2 master secret and key material derivation:
 *   master_secret = PRF(pre_master_secret, "master secret", ClientRandom || ServerRandom)
 *   key_block = PRF(master_secret, "key expansion", ServerRandom || ClientRandom)
 *
 * Reference: RFC 5246 §5, §6.3
 */
#ifndef NEXTSSL_KDF_TLS12_H
#define NEXTSSL_KDF_TLS12_H

#include <stdint.h>
#include <stddef.h>

/* tls12_prf — TLS 1.2 PRF using HMAC-SHA256.
 *
 * secret     : PRF secret input
 * secret_len : length of secret
 * label      : ASCII label string (e.g. "master secret")
 * label_len  : length of label
 * seed       : seed data (typically ClientRandom || ServerRandom)
 * seed_len   : length of seed
 * out        : output buffer
 * out_len    : desired output length
 * Returns 0 on success, -1 on error. */
int tls12_prf(const uint8_t *secret,  size_t secret_len,
              const char    *label,   size_t label_len,
              const uint8_t *seed,    size_t seed_len,
              uint8_t       *out,     size_t out_len);

/* tls12_prf_sha384 — same using HMAC-SHA384 (for TLS_RSA_WITH_AES_256_CBC_SHA384 etc.) */
int tls12_prf_sha384(const uint8_t *secret,  size_t secret_len,
                      const char    *label,   size_t label_len,
                      const uint8_t *seed,    size_t seed_len,
                      uint8_t       *out,     size_t out_len);

/* tls12_master_secret — compute the TLS 1.2 master secret.
 * pre_master: 48-byte pre-master secret
 * client_random, server_random: 32 bytes each
 * master: 48-byte output */
int tls12_master_secret(const uint8_t pre_master[48],
                         const uint8_t client_random[32],
                         const uint8_t server_random[32],
                         uint8_t       master[48]);

/* tls12_key_expansion — expand master secret to key material.
 * master: 48-byte master secret
 * client_random, server_random: 32 bytes each
 * key_block: output buffer (caller specifies length for cipher suite) */
int tls12_key_expansion(const uint8_t master[48],
                         const uint8_t server_random[32],
                         const uint8_t client_random[32],
                         uint8_t *key_block, size_t key_block_len);

#endif /* NEXTSSL_KDF_TLS12_H */
