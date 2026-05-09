/* xcbc_mac.h — AES-XCBC-MAC (RFC 3566 / RFC 4434)
 *
 * AES-XCBC-MAC derives three sub-keys from the master key and produces a
 * 16-byte MAC.  It is used in IKEv1/IKEv2 PRF and integrity transforms.
 *
 * key is always 16 bytes (AES-128 only per RFC 3566 §3).
 * Produces a 16-byte MAC tag.
 */
#ifndef NEXTSSL_XCBC_MAC_H
#define NEXTSSL_XCBC_MAC_H

#include <stdint.h>
#include <stddef.h>

#define XCBC_MAC_KEY_SIZE  16u
#define XCBC_MAC_TAG_SIZE  16u
#define XCBC_MAC_BLOCK_SIZE 16u

/* One-shot AES-XCBC-MAC.
 * key  : 16-byte AES key
 * data : input message
 * len  : message length in bytes (may be 0)
 * tag  : 16-byte output MAC
 * Returns 0 on success, -1 on invalid arguments. */
int xcbc_mac(const uint8_t key[XCBC_MAC_KEY_SIZE],
             const uint8_t *data, size_t len,
             uint8_t        tag[XCBC_MAC_TAG_SIZE]);

/* Streaming interface */
typedef struct {
    uint8_t k1[16], k2[16], k3[16];  /* sub-keys */
    uint8_t e[16];                    /* running CBC state */
    uint8_t buf[16];                  /* incomplete block buffer */
    size_t  buf_len;
    int     has_data;
} xcbc_mac_ctx;

int xcbc_mac_init  (xcbc_mac_ctx *ctx, const uint8_t key[XCBC_MAC_KEY_SIZE]);
int xcbc_mac_update(xcbc_mac_ctx *ctx, const uint8_t *data, size_t len);
int xcbc_mac_final (xcbc_mac_ctx *ctx, uint8_t tag[XCBC_MAC_TAG_SIZE]);

#endif /* NEXTSSL_XCBC_MAC_H */
