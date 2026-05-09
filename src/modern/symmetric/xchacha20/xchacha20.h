/* xchacha20.h — XChaCha20 stream cipher (extended-nonce ChaCha20)
 *
 * XChaCha20 is ChaCha20 with a 192-bit (24-byte) nonce, derived via
 * HChaCha20.  This allows random nonces without 96-bit collision concerns.
 *
 * This header is a thin wrapper over the chacha20_x() function in
 * src/modern/symmetric/chacha20/chacha20.h, providing a dedicated surface
 * with XChaCha20 naming conventions.
 *
 * Reference: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha
 *            libsodium crypto_stream_xchacha20
 */
#ifndef NEXTSSL_XCHACHA20_H
#define NEXTSSL_XCHACHA20_H

#include <stdint.h>
#include <stddef.h>
#include "../chacha20/chacha20.h"

#define XCHACHA20_KEY_SIZE    32u
#define XCHACHA20_NONCE_SIZE  24u

/* xchacha20_xor — Encrypt/decrypt in[] → out[] using XChaCha20.
 * in and out may alias. counter is usually 0 for a new message.
 * Returns next counter value. */
static inline uint64_t xchacha20_xor(uint8_t       *out,
                                      const uint8_t *in,  size_t len,
                                      const uint8_t  key[XCHACHA20_KEY_SIZE],
                                      const uint8_t  nonce[XCHACHA20_NONCE_SIZE],
                                      uint64_t       counter)
{
    return chacha20_x(out, in, len, key, nonce, counter);
}

/* xchacha20_keystream — Generate raw keystream into buf. */
static inline void xchacha20_keystream(uint8_t       *buf, size_t len,
                                        const uint8_t  key[XCHACHA20_KEY_SIZE],
                                        const uint8_t  nonce[XCHACHA20_NONCE_SIZE])
{
    /* XOR a zero buffer to get raw keystream */
    uint8_t zero = 0;
    /* Allocate on stack only for small lengths; for general use pass pre-zeroed buf */
    chacha20_x(buf, buf, len, key, nonce, 0);
    (void)zero;
}

#endif /* NEXTSSL_XCHACHA20_H */
