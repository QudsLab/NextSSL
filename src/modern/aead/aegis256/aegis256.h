/* aegis256.h — AEGIS-256 AEAD cipher (CAESAR portfolio)
 *
 * AEGIS-256 extends AEGIS-128L to a 256-bit key.
 * State: 6 × 128-bit blocks.  Key: 256 bits.  Nonce: 256 bits.
 *
 * Reference: draft-irtf-cfrg-aegis-aead §3.2
 */
#ifndef NEXTSSL_AEGIS256_H
#define NEXTSSL_AEGIS256_H

#include <stdint.h>
#include <stddef.h>

#define AEGIS256_KEY_SIZE    32u
#define AEGIS256_NONCE_SIZE  32u
#define AEGIS256_TAG128_SIZE 16u
#define AEGIS256_TAG256_SIZE 32u

int aegis256_encrypt(
        const uint8_t  key[AEGIS256_KEY_SIZE],
        const uint8_t  nonce[AEGIS256_NONCE_SIZE],
        const uint8_t *aad,       size_t aad_len,
        const uint8_t *plaintext, size_t pt_len,
        uint8_t       *ciphertext,
        uint8_t        tag[AEGIS256_TAG128_SIZE]);

int aegis256_decrypt(
        const uint8_t  key[AEGIS256_KEY_SIZE],
        const uint8_t  nonce[AEGIS256_NONCE_SIZE],
        const uint8_t *aad,        size_t aad_len,
        const uint8_t *ciphertext, size_t ct_len,
        const uint8_t  tag[AEGIS256_TAG128_SIZE],
        uint8_t       *plaintext);

#endif /* NEXTSSL_AEGIS256_H */
