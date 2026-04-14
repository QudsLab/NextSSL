/* three_des.h — Triple-DES (3-DES / TDEA) cipher (Plan 201 / Plan 203)
 *
 * Status: implemented locally.
 * Legacy-only compatibility primitive; do not use for new designs.
 *
 * Key: 192-bit (24 bytes) = three independent 64-bit DES keys (K1‖K2‖K3).
 * Mode: CBC (primary use-case); further modes may be added.
 */
#ifndef MODERN_THREE_DES_H
#define MODERN_THREE_DES_H

#include <stddef.h>
#include <stdint.h>

#define THREE_DES_KEY_SIZE   24   /* 3 × 8 bytes */
#define THREE_DES_BLOCK_SIZE  8   /* DES block = 64 bits */

/* CBC encrypt */
int three_des_cbc_encrypt(const uint8_t key[THREE_DES_KEY_SIZE],
                          const uint8_t iv[THREE_DES_BLOCK_SIZE],
                          const uint8_t *plaintext,  size_t len,
                          uint8_t       *ciphertext);

/* CBC decrypt */
int three_des_cbc_decrypt(const uint8_t key[THREE_DES_KEY_SIZE],
                          const uint8_t iv[THREE_DES_BLOCK_SIZE],
                          const uint8_t *ciphertext, size_t len,
                          uint8_t       *plaintext);

#endif /* MODERN_THREE_DES_H */
