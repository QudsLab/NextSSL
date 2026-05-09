/* kmacxof128.c — KMACXOF-128 (SP 800-185 §4.3.1 XOF variant) */
#include "kmacxof128.h"
#include "../shake/shake.h"
#include <string.h>

/* SP 800-185 right_encode(0) = bytes {0x00, 0x01} (two bytes) */
static const uint8_t right_encode_zero[2] = { 0x00, 0x01 };

void kmacxof128_init(KMACXOF128_CTX *ctx,
                     const uint8_t *key,    size_t klen,
                     const uint8_t *custom, size_t clen)
{
    /* Initialise like KMAC128 but store 0 as out_bytes (XOF signal).
     * kmac128_init calls kmac_init_common which sets ctx->out_bytes = 32.
     * We override it to 0 to distinguish XOF mode in the final step. */
    kmac128_init(ctx, key, klen, custom, clen);
    ctx->out_bytes = 0;  /* 0 = XOF mode */
}

void kmacxof128_update(KMACXOF128_CTX *ctx, const uint8_t *data, size_t dlen)
{
    kmac_update(ctx, data, dlen);
}

void kmacxof128_final(KMACXOF128_CTX *ctx, uint8_t *out, size_t outlen)
{
    /* Append right_encode(0) instead of right_encode(L*8) */
    shake_update(&ctx->shake, right_encode_zero, sizeof(right_encode_zero));
    /* cSHAKE padding byte 0x04 */
    shake_custom_final(&ctx->shake, 0x04);
    shake_squeeze(&ctx->shake, out, outlen);
}

int kmacxof128_compute(const uint8_t *key,    size_t klen,
                       const uint8_t *data,   size_t dlen,
                       const uint8_t *custom, size_t clen,
                       uint8_t *out, size_t outlen)
{
    if (!out || outlen == 0) return -1;
    KMACXOF128_CTX ctx;
    kmacxof128_init(&ctx, key, klen, custom, clen);
    kmacxof128_update(&ctx, data, dlen);
    kmacxof128_final(&ctx, out, outlen);
    return 0;
}

void kmacxof128_ops_init_fn(KMACXOF128_CTX *ctx)
{
    kmacxof128_init(ctx, NULL, 0, NULL, 0);
}
