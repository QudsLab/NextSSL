/* umac.h — UMAC universal message authentication code (RFC 4418)
 *
 * UMAC-32/64/96/128 produces variable-length tags using a polynomial hash
 * (NH + poly) over a stream derived from AES in counter mode.
 *
 * Reference: RFC 4418, Ted Krovetz and Wei Dai.
 *
 * Key: 16 bytes (AES-128 only per RFC 4418 §4).
 * Nonce: 1–16 bytes (typically 8-byte counter for streaming use).
 * Tag: 4, 8, 12, or 16 bytes (UMAC-32/64/96/128).
 */
#ifndef NEXTSSL_UMAC_H
#define NEXTSSL_UMAC_H

#include <stdint.h>
#include <stddef.h>

#define UMAC_KEY_SIZE    16u
#define UMAC_NONCE_SIZE  8u   /* RFC 4418 §4.2 recommends 8-byte nonce */

/* One-shot UMAC with selectable tag length.
 * key    : 16-byte AES key
 * nonce  : nonce of nonce_len bytes (1–16 bytes)
 * noncelen: nonce length
 * msg    : input message
 * msglen : message length
 * tag    : output buffer of tag_len bytes
 * tag_len: 4, 8, 12, or 16
 * Returns 0 on success, -1 on error. */
int umac(const uint8_t  key[UMAC_KEY_SIZE],
         const uint8_t *nonce,   size_t nonce_len,
         const uint8_t *msg,     size_t msglen,
         uint8_t       *tag,     size_t tag_len);

/* Convenience wrappers */
int umac32 (const uint8_t key[16], const uint8_t nonce[8],
            const uint8_t *msg, size_t msglen, uint8_t tag[4]);
int umac64 (const uint8_t key[16], const uint8_t nonce[8],
            const uint8_t *msg, size_t msglen, uint8_t tag[8]);
int umac96 (const uint8_t key[16], const uint8_t nonce[8],
            const uint8_t *msg, size_t msglen, uint8_t tag[12]);
int umac128(const uint8_t key[16], const uint8_t nonce[8],
            const uint8_t *msg, size_t msglen, uint8_t tag[16]);

#endif /* NEXTSSL_UMAC_H */
