/* ecies.h — Elliptic-Curve Integrated Encryption Scheme (SEC1v2 §5.1)
 *
 * ECIES combines ECDH, a KDF, and symmetric encryption (AES-GCM or XOR stream)
 * into a hybrid encryption scheme.
 *
 * This implementation targets ECIES-P256-SHA256-AES128GCM (most common profile):
 *   1. Generate ephemeral key pair (R_priv, R_pub)
 *   2. Z = ECDH(R_priv, recipient_pub)
 *   3. (enc_key, mac_key) = HKDF-SHA256(Z)
 *   4. ct  = AES-128-GCM(enc_key, plaintext)
 *   5. out = R_pub || ct (GCM tag is appended by AES-GCM)
 *
 * Reference: SEC1 v2.0 §5.1, examples/c/ecies/
 */
#ifndef NEXTSSL_ECIES_H
#define NEXTSSL_ECIES_H

#include <stdint.h>
#include <stddef.h>

#define ECIES_EPHEMERAL_PUB_SIZE  65u  /* 0x04 || x(32) || y(32) */
#define ECIES_TAG_SIZE            16u  /* AES-GCM tag */
#define ECIES_NONCE_SIZE          12u  /* AES-GCM nonce */
/* Total overhead: ephemeral pub (65) + nonce (12) + tag (16) = 93 bytes */
#define ECIES_OVERHEAD            (ECIES_EPHEMERAL_PUB_SIZE + ECIES_NONCE_SIZE + ECIES_TAG_SIZE)

/* ecies_encrypt — encrypt plaintext to a P-256 public key.
 *
 * recipient_pub: 64-byte uncompressed public key (x||y, without 0x04 prefix)
 * plaintext    : message to encrypt
 * pt_len       : message length
 * ciphertext   : output buffer — must be at least pt_len + ECIES_OVERHEAD bytes
 * ct_len       : out — actual ciphertext length written
 * Returns 0 on success, -1 on error. */
int ecies_encrypt(const uint8_t  recipient_pub[64],
                  const uint8_t *plaintext, size_t pt_len,
                  uint8_t       *ciphertext, size_t *ct_len);

/* ecies_decrypt — decrypt a ciphertext produced by ecies_encrypt.
 *
 * recipient_priv: 32-byte P-256 private key
 * ciphertext    : buffer produced by ecies_encrypt
 * ct_len        : ciphertext length
 * plaintext     : caller-allocated output, at least ct_len bytes
 * pt_len        : out — actual plaintext length written
 * Returns 0 on success, -1 on failure (including auth failure). */
int ecies_decrypt(const uint8_t  recipient_priv[32],
                  const uint8_t *ciphertext, size_t ct_len,
                  uint8_t       *plaintext,  size_t *pt_len);

#endif /* NEXTSSL_ECIES_H */
