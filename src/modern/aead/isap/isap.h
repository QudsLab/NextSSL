/* isap.h — ISAP AEAD (NIST Lightweight Cryptography Finalist)
 *
 * ISAP is a family of authenticated encryption schemes designed for
 * resistance against side-channel attacks (in particular, power analysis).
 * It uses the Ascon or KECCAK-p permutation as the core primitive.
 *
 * ISAP-A-128A (Ascon-based, 128-bit key):
 *   Key: 128 bits.  Nonce: 128 bits.  Tag: 128 bits.
 *   Rate: 64 bits for ISAP-A-128, 128 bits for ISAP-A-128A.
 *
 * Reference: https://isap.iaik.tugraz.at/
 *            Dobraunig et al., "ISAP v2.0", 2021
 *
 * TODO: Full ISAP requires the Ascon permutation.
 *       This header provides the complete API surface; the implementation
 *       uses a structural stub pending Ascon permutation integration.
 */
#ifndef NEXTSSL_ISAP_H
#define NEXTSSL_ISAP_H

#include <stdint.h>
#include <stddef.h>

#define ISAP_KEY_SIZE    16u
#define ISAP_NONCE_SIZE  16u
#define ISAP_TAG_SIZE    16u

/* isap_encrypt — ISAP-A-128A authenticated encryption.
 * Returns 0 on success. */
int isap_encrypt(
        const uint8_t  key[ISAP_KEY_SIZE],
        const uint8_t  nonce[ISAP_NONCE_SIZE],
        const uint8_t *aad,       size_t aad_len,
        const uint8_t *plaintext, size_t pt_len,
        uint8_t       *ciphertext,
        uint8_t        tag[ISAP_TAG_SIZE]);

/* isap_decrypt — ISAP-A-128A verified decryption.
 * Returns 0 on success, -1 on authentication failure. */
int isap_decrypt(
        const uint8_t  key[ISAP_KEY_SIZE],
        const uint8_t  nonce[ISAP_NONCE_SIZE],
        const uint8_t *aad,        size_t aad_len,
        const uint8_t *ciphertext, size_t ct_len,
        const uint8_t  tag[ISAP_TAG_SIZE],
        uint8_t       *plaintext);

#endif /* NEXTSSL_ISAP_H */
