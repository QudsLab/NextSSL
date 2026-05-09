/* vmac.h — VMAC high-speed message authentication code (Krovetz 2007)
 *
 * VMAC is a hash-then-encrypt MAC based on VHASH (universal hashing) and
 * AES in counter mode.  It is designed for 64-bit CPUs and produces either
 * a 64-bit or 128-bit tag.
 *
 * Reference: https://vmac.sourceforge.net/
 * VMAC spec: Ted Krovetz, "VMAC: Message Authentication Code using Universal
 *            Hashing", IETF draft-krovetz-vmac-01, 2007.
 *
 * Key: 16, 24, or 32 bytes (AES-128/192/256 for the stream key).
 * Nonce: 16-byte (128-bit) unique per-message nonce.
 * Tag: 8 bytes (64-bit) or 16 bytes (128-bit).
 */
#ifndef NEXTSSL_VMAC_H
#define NEXTSSL_VMAC_H

#include <stdint.h>
#include <stddef.h>

#define VMAC_TAG64_SIZE   8u
#define VMAC_TAG128_SIZE  16u
#define VMAC_NONCE_SIZE   16u

/* One-shot VMAC (64-bit tag).
 * key    : AES key (16/24/32 bytes)
 * keylen : key length in bytes
 * nonce  : 16-byte unique nonce
 * msg    : input message
 * msglen : message length in bytes
 * tag    : 8-byte output MAC
 * Returns 0 on success, -1 on error. */
int vmac64(const uint8_t *key,   size_t keylen,
           const uint8_t  nonce[VMAC_NONCE_SIZE],
           const uint8_t *msg,   size_t msglen,
           uint8_t        tag[VMAC_TAG64_SIZE]);

/* One-shot VMAC (128-bit tag). */
int vmac128(const uint8_t *key,   size_t keylen,
            const uint8_t  nonce[VMAC_NONCE_SIZE],
            const uint8_t *msg,   size_t msglen,
            uint8_t        tag[VMAC_TAG128_SIZE]);

#endif /* NEXTSSL_VMAC_H */
