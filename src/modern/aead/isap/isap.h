/* isap.h — ISAP AEAD (NIST Lightweight Cryptography Finalist)
 *
 * ISAP is a family of authenticated encryption schemes designed for
 * resistance against side-channel attacks (in particular, power analysis).
 * Uses the Ascon-128 permutation (p_A=p_B=p_K=12, p_E=1 rounds).
 *
 * Key: 128 bits.  Nonce: 128 bits.  Tag: 128 bits.
 * Rate: 64 bits (8 bytes).
 *
 * Reference: https://isap.iaik.tugraz.at/
 *            Dobraunig et al., "ISAP v2.0", 2021
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
