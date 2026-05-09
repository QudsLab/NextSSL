/* xchacha20_poly1305.h — XChaCha20-Poly1305 AEAD (extended nonce variant)
 *
 * XChaCha20-Poly1305 is identical to ChaCha20-Poly1305 (RFC 8439) but uses
 * a 192-bit (24-byte) nonce, making random nonce generation safe for large
 * message volumes without collision concerns.
 *
 * This is a thin wrapper over chacha20_poly1305.h using the X variant.
 *
 * Reference: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha
 *            libsodium crypto_aead_xchacha20poly1305_ietf_*
 */
#ifndef NEXTSSL_XCHACHA20_POLY1305_H
#define NEXTSSL_XCHACHA20_POLY1305_H

#include <stdint.h>
#include <stddef.h>

#define XCHACHA20POLY1305_KEY_SIZE    32u
#define XCHACHA20POLY1305_NONCE_SIZE  24u  /* extended nonce */
#define XCHACHA20POLY1305_TAG_SIZE    16u

/* xchacha20poly1305_encrypt — Encrypt and authenticate.
 *
 * key       : 32-byte key
 * nonce     : 24-byte nonce (can be random)
 * aad       : additional authenticated data (may be NULL)
 * aad_len   : length of aad
 * plaintext : input message
 * pt_len    : message length
 * ciphertext: output (must be pt_len bytes)
 * tag       : 16-byte authentication tag output
 * Returns 0 on success. */
int xchacha20poly1305_encrypt(
        const uint8_t  key[XCHACHA20POLY1305_KEY_SIZE],
        const uint8_t  nonce[XCHACHA20POLY1305_NONCE_SIZE],
        const uint8_t *aad,        size_t aad_len,
        const uint8_t *plaintext,  size_t pt_len,
        uint8_t       *ciphertext,
        uint8_t        tag[XCHACHA20POLY1305_TAG_SIZE]);

/* xchacha20poly1305_decrypt — Decrypt and verify.
 * Returns 0 on success, -1 on authentication failure. */
int xchacha20poly1305_decrypt(
        const uint8_t  key[XCHACHA20POLY1305_KEY_SIZE],
        const uint8_t  nonce[XCHACHA20POLY1305_NONCE_SIZE],
        const uint8_t *aad,        size_t aad_len,
        const uint8_t *ciphertext, size_t ct_len,
        const uint8_t  tag[XCHACHA20POLY1305_TAG_SIZE],
        uint8_t       *plaintext);

#endif /* NEXTSSL_XCHACHA20_POLY1305_H */
