/* xsalsa20.h — XSalsa20 extended-nonce variant of Salsa20
 *
 * XSalsa20 extends Salsa20 with a 192-bit (24-byte) nonce using HSalsa20.
 * This allows random nonces without collision concerns.
 *
 * Reference: https://cr.yp.to/snuffle/xsalsa-20081128.pdf
 */
#ifndef NEXTSSL_XSALSA20_H
#define NEXTSSL_XSALSA20_H

#include <stdint.h>
#include <stddef.h>
#include "../salsa20/salsa20.h"

#define XSALSA20_KEY_SIZE    32u
#define XSALSA20_NONCE_SIZE  24u  /* extended 192-bit nonce */

typedef struct {
    salsa20_ctx inner;
} xsalsa20_ctx;

/* xsalsa20_init — Initialize XSalsa20 with a 256-bit key and 192-bit nonce.
 * Returns 0 on success. */
int xsalsa20_init(xsalsa20_ctx  *ctx,
                   const uint8_t  key[XSALSA20_KEY_SIZE],
                   const uint8_t  nonce[XSALSA20_NONCE_SIZE]);

void xsalsa20_xor(xsalsa20_ctx *ctx,
                   const uint8_t *in, uint8_t *out, size_t len);

void xsalsa20_keystream(xsalsa20_ctx *ctx, uint8_t *buf, size_t len);

#endif /* NEXTSSL_XSALSA20_H */
