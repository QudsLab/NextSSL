/* ascon_aead128.h — Ascon-AEAD128 (SP 800-232)
 *
 * 128-bit key, 128-bit nonce, 128-bit tag.
 * Rate = 128 bits (16 bytes) per permutation call.
 */
#ifndef NEXTSSL_ASCON_AEAD128_H
#define NEXTSSL_ASCON_AEAD128_H

#include <stdint.h>
#include <stddef.h>

#define ASCON_AEAD128_KEY_LEN   16
#define ASCON_AEAD128_NONCE_LEN 16
#define ASCON_AEAD128_TAG_LEN   16

/* Encrypt and authenticate.
 * ciphertext output length = plaintextlen + ASCON_AEAD128_TAG_LEN
 * Returns 0 on success. */
int ascon_aead128_encrypt(const uint8_t key[ASCON_AEAD128_KEY_LEN],
                           const uint8_t nonce[ASCON_AEAD128_NONCE_LEN],
                           const uint8_t *ad,      size_t adlen,
                           const uint8_t *pntxt,   size_t pntxtlen,
                           uint8_t       *crtxt);   /* pntxtlen + TAG_LEN bytes */

/* Decrypt and verify.
 * ciphertextlen must be >= ASCON_AEAD128_TAG_LEN.
 * plaintext output length = ciphertextlen - ASCON_AEAD128_TAG_LEN
 * Returns 0 on success (tag valid), -1 on authentication failure. */
int ascon_aead128_decrypt(const uint8_t key[ASCON_AEAD128_KEY_LEN],
                           const uint8_t nonce[ASCON_AEAD128_NONCE_LEN],
                           const uint8_t *ad,      size_t adlen,
                           const uint8_t *crtxt,   size_t crtxtlen,
                           uint8_t       *pntxt);

#endif /* NEXTSSL_ASCON_AEAD128_H */
