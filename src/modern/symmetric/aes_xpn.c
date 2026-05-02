/* aes_xpn.c — AES Extended Packet Numbering (IEEE 802.1AEbw) */
#include "aes_xpn.h"
#include "aes_gcm.h"
#include <string.h>
#include <stdlib.h>

/* Build the 12-byte (96-bit) GCM nonce from SSCI and 64-bit PN */
static void xpn_build_nonce(uint8_t nonce[12], uint32_t ssci, uint64_t pn)
{
    /* Bytes 0-3: SSCI, big-endian */
    nonce[0] = (uint8_t)(ssci >> 24);
    nonce[1] = (uint8_t)(ssci >> 16);
    nonce[2] = (uint8_t)(ssci >>  8);
    nonce[3] = (uint8_t)(ssci      );
    /* Bytes 4-11: PN, big-endian */
    nonce[4]  = (uint8_t)(pn >> 56);
    nonce[5]  = (uint8_t)(pn >> 48);
    nonce[6]  = (uint8_t)(pn >> 40);
    nonce[7]  = (uint8_t)(pn >> 32);
    nonce[8]  = (uint8_t)(pn >> 24);
    nonce[9]  = (uint8_t)(pn >> 16);
    nonce[10] = (uint8_t)(pn >>  8);
    nonce[11] = (uint8_t)(pn      );
}

void AES_XPN_encrypt(const uint8_t *key,
                     uint32_t ssci, uint64_t pn,
                     const void *aad,   size_t aadlen,
                     const void *pntxt, size_t datalen,
                     void       *crtxt_and_tag)
{
    uint8_t nonce[12];
    xpn_build_nonce(nonce, ssci, pn);
    AES_GCM_encrypt(key, nonce, aad, aadlen, pntxt, datalen, crtxt_and_tag);
}

char AES_XPN_decrypt(const uint8_t *key,
                     uint32_t ssci, uint64_t pn,
                     const void *aad,   size_t aadlen,
                     const void *crtxt, size_t datalen,
                     const void *tag,
                     void       *pntxt)
{
    uint8_t nonce[12];
    xpn_build_nonce(nonce, ssci, pn);

    /* GCM decrypt expects tag appended to crtxt; build a combined buffer */
    uint8_t *combined = (uint8_t *)malloc(datalen + 16);
    if (!combined) return -1;
    if (datalen) memcpy(combined, crtxt, datalen);
    memcpy(combined + datalen, tag, 16);
    char rc = AES_GCM_decrypt(key, nonce, aad, aadlen, combined, datalen, pntxt);
    free(combined);
    return rc;
}
