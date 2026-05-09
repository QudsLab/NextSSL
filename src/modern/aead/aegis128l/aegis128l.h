/* aegis128l.h — AEGIS-128L AEAD cipher (CAESAR portfolio winner)
 *
 * AEGIS-128L is a high-performance AEAD using AES round functions.
 * It offers exceptionally high throughput (up to 5 bytes/cycle on AES-NI).
 *
 * Key: 128 bits.  Nonce: 128 bits.  Tag: 128 or 256 bits.
 * Max message length: 2^61 bytes.
 *
 * Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.txt
 *            Wu & Preneel, "AEGIS: A Fast Authenticated Encryption Algorithm"
 *
 * TODO: Full AEGIS-128L requires AES round function access (AES-NI or software).
 *       This implementation uses the project's aes_ecb_encrypt_block as the
 *       AES round function approximation.
 */
#ifndef NEXTSSL_AEGIS128L_H
#define NEXTSSL_AEGIS128L_H

#include <stdint.h>
#include <stddef.h>

#define AEGIS128L_KEY_SIZE    16u
#define AEGIS128L_NONCE_SIZE  16u
#define AEGIS128L_TAG128_SIZE 16u
#define AEGIS128L_TAG256_SIZE 32u

/* aegis128l_encrypt — Encrypt and produce a 128-bit tag.
 * ciphertext must be exactly pt_len bytes.
 * Returns 0 on success. */
int aegis128l_encrypt(
        const uint8_t  key[AEGIS128L_KEY_SIZE],
        const uint8_t  nonce[AEGIS128L_NONCE_SIZE],
        const uint8_t *aad,       size_t aad_len,
        const uint8_t *plaintext, size_t pt_len,
        uint8_t       *ciphertext,
        uint8_t        tag[AEGIS128L_TAG128_SIZE]);

/* aegis128l_decrypt — Decrypt and verify 128-bit tag.
 * Returns 0 on success, -1 on authentication failure. */
int aegis128l_decrypt(
        const uint8_t  key[AEGIS128L_KEY_SIZE],
        const uint8_t  nonce[AEGIS128L_NONCE_SIZE],
        const uint8_t *aad,        size_t aad_len,
        const uint8_t *ciphertext, size_t ct_len,
        const uint8_t  tag[AEGIS128L_TAG128_SIZE],
        uint8_t       *plaintext);

#endif /* NEXTSSL_AEGIS128L_H */
