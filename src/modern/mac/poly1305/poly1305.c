/* poly1305.c — Poly1305 one-time MAC wrappers
 *
 * Thin shim over monocypher's crypto_poly1305 / crypto_poly1305_{init,update,final}.
 * The monocypher_ctx layout matches poly1305_ctx exactly (same fields, same order),
 * so we cast directly.
 */
#include "poly1305.h"
#include "monocypher.h"
#include <string.h>

/* Static assertion: the two context structs must be the same size so the
 * cast in the streaming API is safe. */
typedef char poly1305_ctx_size_check[
    (sizeof(poly1305_ctx) == sizeof(crypto_poly1305_ctx)) ? 1 : -1
];

void poly1305(uint8_t        mac[16],
              const uint8_t *message, size_t msg_len,
              const uint8_t  key[32])
{
    crypto_poly1305(mac, message, msg_len, key);
}

void poly1305_init(poly1305_ctx *ctx, const uint8_t key[32])
{
    crypto_poly1305_init((crypto_poly1305_ctx *)ctx, key);
}

void poly1305_update(poly1305_ctx *ctx,
                     const uint8_t *message, size_t msg_len)
{
    crypto_poly1305_update((crypto_poly1305_ctx *)ctx, message, msg_len);
}

void poly1305_final(poly1305_ctx *ctx, uint8_t mac[16])
{
    crypto_poly1305_final((crypto_poly1305_ctx *)ctx, mac);
}
