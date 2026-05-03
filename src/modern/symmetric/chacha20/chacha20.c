/* chacha20.c — ChaCha20 stream cipher wrappers
 *
 * Thin shim over monocypher's crypto_chacha20_djb / crypto_chacha20_ietf /
 * crypto_chacha20_x / crypto_chacha20_h.  All implementations and security
 * guarantees come from monocypher.
 */
#include "chacha20.h"
#include "monocypher.h"

uint64_t chacha20_djb(uint8_t       *cipher_text,
                      const uint8_t *plain_text,
                      size_t         text_size,
                      const uint8_t  key[32],
                      const uint8_t  nonce[8],
                      uint64_t       ctr)
{
    return crypto_chacha20_djb(cipher_text, plain_text, text_size, key, nonce, ctr);
}

uint32_t chacha20_ietf(uint8_t       *cipher_text,
                       const uint8_t *plain_text,
                       size_t         text_size,
                       const uint8_t  key[32],
                       const uint8_t  nonce[12],
                       uint32_t       ctr)
{
    return crypto_chacha20_ietf(cipher_text, plain_text, text_size, key, nonce, ctr);
}

uint64_t chacha20_x(uint8_t       *cipher_text,
                    const uint8_t *plain_text,
                    size_t         text_size,
                    const uint8_t  key[32],
                    const uint8_t  nonce[24],
                    uint64_t       ctr)
{
    return crypto_chacha20_x(cipher_text, plain_text, text_size, key, nonce, ctr);
}

void chacha20_h(uint8_t out[32],
                const uint8_t key[32],
                const uint8_t in[16])
{
    crypto_chacha20_h(out, key, in);
}
