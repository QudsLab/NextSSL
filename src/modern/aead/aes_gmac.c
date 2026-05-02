/* aes_gmac.c — AES-GMAC (SP 800-38D)
 *
 * GMAC = GCM with empty plaintext.  Delegates entirely to AES-GCM.
 * The authentication tag is computed over the AAD only; no bytes are encrypted.
 */
#include "aes_gmac.h"
#include "aes_gcm.h"
#include "aes_internal.h"  /* M_RESULT_SUCCESS, M_AUTHENTICATION_ERROR */
#include <string.h>

void AES_GMAC_compute(const uint8_t *key,
                      const uint8_t  nonce[12],
                      const void    *aad,   size_t aadlen,
                      uint8_t        tag[16])
{
    /* GCM encrypt with 0-length plaintext: output is only the 16-byte tag */
    AES_GCM_encrypt(key, nonce, aad, aadlen, NULL, 0, tag);
}

char AES_GMAC_verify(const uint8_t *key,
                     const uint8_t  nonce[12],
                     const void    *aad,   size_t aadlen,
                     const uint8_t  tag[16])
{
    /* GCM decrypt with 0-length ciphertext; the tag sits at crtxt+crtxtLen = tag[0] */
    return AES_GCM_decrypt(key, nonce, aad, aadlen, tag, 0, NULL);
}
