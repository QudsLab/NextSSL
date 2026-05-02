/* aes_gmac.h — AES-GMAC (SP 800-38D)
 *
 * GMAC is GCM with empty plaintext: the authentication tag is computed
 * over Additional Authenticated Data (AAD) only.  No ciphertext is produced.
 *
 * AES-GMAC is used in, e.g., IEEE 802.1AE (MACsec) and TLS.
 */
#ifndef NEXTSSL_AES_GMAC_H
#define NEXTSSL_AES_GMAC_H

#include <stdint.h>
#include <stddef.h>

/* Compute GMAC tag over aad.
 * key   : 16, 24, or 32 bytes (AES-128/192/256, compile-time)
 * nonce : 12-byte (96-bit) nonce
 * aad   : additional authenticated data
 * aadlen: length of aad in bytes
 * tag   : output buffer for the 16-byte authentication tag
 */
void AES_GMAC_compute(const uint8_t *key,
                      const uint8_t  nonce[12],
                      const void    *aad,   size_t aadlen,
                      uint8_t        tag[16]);

/* Verify GMAC tag.
 * Returns M_RESULT_SUCCESS (0) if tag matches, M_AUTHENTICATION_ERROR otherwise. */
char AES_GMAC_verify(const uint8_t *key,
                     const uint8_t  nonce[12],
                     const void    *aad,   size_t aadlen,
                     const uint8_t  tag[16]);

#endif /* NEXTSSL_AES_GMAC_H */
