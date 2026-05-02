/* aes_xpn.h — AES Extended Packet Numbering (IEEE 802.1AEbw / XPN)
 *
 * XPN extends AES-GCM for MACsec by splitting the 64-bit packet number into:
 *   - a 32-bit Short Secure Channel Sequence Number (SSCI) transmitted in-band
 *   - a 32-bit lower PN that rolls over, combined with SSCI to form the full 64-bit PN
 *
 * The 96-bit IV is constructed as: SSCI (4 bytes) || PN[63:32] (4 bytes) || PN[31:0] (4 bytes)
 * where PN is the 64-bit packet number.
 *
 * Encryption and decryption otherwise delegate to AES-GCM.
 */
#ifndef NEXTSSL_AES_XPN_H
#define NEXTSSL_AES_XPN_H

#include <stdint.h>
#include <stddef.h>

/* ssci      : 32-bit Short Secure Channel Identifier
 * pn        : 64-bit extended packet number
 * key       : AES key (compile-time length)
 * aad       : additional authenticated data
 * aadlen    : length of aad
 * pntxt/crtxt: plaintext / ciphertext
 * datalen   : payload length in bytes
 * tag_out   : 16-byte tag appended after crtxt (caller must allocate datalen+16) */
void AES_XPN_encrypt(const uint8_t *key,
                     uint32_t ssci, uint64_t pn,
                     const void *aad,   size_t aadlen,
                     const void *pntxt, size_t datalen,
                     void       *crtxt_and_tag);

/* Returns M_RESULT_SUCCESS (0) or M_AUTHENTICATION_ERROR */
char AES_XPN_decrypt(const uint8_t *key,
                     uint32_t ssci, uint64_t pn,
                     const void *aad,    size_t aadlen,
                     const void *crtxt,  size_t datalen,
                     const void *tag,
                     void       *pntxt);

#endif /* NEXTSSL_AES_XPN_H */
