/* aes_cbc_cs.h — AES-CBC Ciphertext Stealing variants CS1, CS2, CS3 (SP 800-38A Addendum)
 *
 * All three variants produce the same ciphertext bytes as standard CBC-CTS.
 * They differ only in the arrangement of the final two ciphertext blocks:
 *   CS1 — swap last two blocks only when the last plaintext block is partial
 *   CS2 — always swap the last two output blocks
 *   CS3 — no swap; partial ciphertext block is always last (RFC 2040 / IETF ordering)
 *
 * datalen must be >= 16 bytes (one full AES block).
 * Returns M_RESULT_SUCCESS (0) on success, M_DATALENGTH_ERROR on bad length.
 */
#ifndef NEXTSSL_AES_CBC_CS_H
#define NEXTSSL_AES_CBC_CS_H

#include <stdint.h>
#include <stddef.h>
#include "aes_common.h"

char AES_CBC_CS1_encrypt(const uint8_t *key, const uint8_t iv[16],
                          const void *pntxt, size_t ptextLen, void *crtxt);
char AES_CBC_CS1_decrypt(const uint8_t *key, const uint8_t iv[16],
                          const void *crtxt, size_t crtxtLen, void *pntxt);

char AES_CBC_CS2_encrypt(const uint8_t *key, const uint8_t iv[16],
                          const void *pntxt, size_t ptextLen, void *crtxt);
char AES_CBC_CS2_decrypt(const uint8_t *key, const uint8_t iv[16],
                          const void *crtxt, size_t crtxtLen, void *pntxt);

char AES_CBC_CS3_encrypt(const uint8_t *key, const uint8_t iv[16],
                          const void *pntxt, size_t ptextLen, void *crtxt);
char AES_CBC_CS3_decrypt(const uint8_t *key, const uint8_t iv[16],
                          const void *crtxt, size_t crtxtLen, void *pntxt);

#endif /* NEXTSSL_AES_CBC_CS_H */
