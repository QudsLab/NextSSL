/* deoxys_ii.h — Deoxys-II AEAD (CAESAR portfolio winner, defense-in-depth)
 *
 * Deoxys-II is a tweakable-block-cipher-based AEAD that provides full
 * nonce-misuse resistance (beyond the typical AEAD security model).
 *
 * Key: 128 bits.  Nonce: 120 bits (15 bytes).  Tag: 128 bits.
 * Uses a tweakable AES (Deoxys-BC) as the underlying primitive.
 * Current implementation approximates Deoxys-BC with AES-ECB + tweak XOR;
 * replace deoxys_bc() in deoxys_ii.c with the full Deoxys-BC for strict compliance.
 *
 * Reference: Jean et al., "Deoxys v1.41", 2016
 *            https://competitions.cr.yp.to/caesar-submissions.html
 */
#ifndef NEXTSSL_DEOXYS_II_H
#define NEXTSSL_DEOXYS_II_H

#include <stdint.h>
#include <stddef.h>

#define DEOXYS_II_KEY_SIZE    16u
#define DEOXYS_II_NONCE_SIZE  15u  /* 120-bit nonce */
#define DEOXYS_II_TAG_SIZE    16u

/* deoxys_ii_encrypt — Encrypt and produce a 128-bit tag.
 * Returns 0 on success. */
int deoxys_ii_encrypt(
        const uint8_t  key[DEOXYS_II_KEY_SIZE],
        const uint8_t  nonce[DEOXYS_II_NONCE_SIZE],
        const uint8_t *aad,       size_t aad_len,
        const uint8_t *plaintext, size_t pt_len,
        uint8_t       *ciphertext,
        uint8_t        tag[DEOXYS_II_TAG_SIZE]);

/* deoxys_ii_decrypt — Decrypt and verify tag.
 * Returns 0 on success, -1 on authentication failure. */
int deoxys_ii_decrypt(
        const uint8_t  key[DEOXYS_II_KEY_SIZE],
        const uint8_t  nonce[DEOXYS_II_NONCE_SIZE],
        const uint8_t *aad,        size_t aad_len,
        const uint8_t *ciphertext, size_t ct_len,
        const uint8_t  tag[DEOXYS_II_TAG_SIZE],
        uint8_t       *plaintext);

#endif /* NEXTSSL_DEOXYS_II_H */
