/* kmacxof256.c — KMACXOF-256 (SP 800-185 §4.3.1 XOF variant, 256-bit security) */
#include "kmacxof256.h"
#include "../shake/shake.h"
#include <string.h>

static const uint8_t right_encode_zero[2] = { 0x00, 0x01 };

void kmacxof256_init(KMACXOF256_CTX *ctx,
                     const uint8_t *key,    size_t klen,
                     const uint8_t *custom, size_t clen)
{
    kmac256_init(ctx, key, klen, custom, clen);
    ctx->out_bytes = 0;  /* 0 = XOF mode */
}

void kmacxof256_update(KMACXOF256_CTX *ctx, const uint8_t *data, size_t dlen)
{
    kmac_update(ctx, data, dlen);
}

void kmacxof256_final(KMACXOF256_CTX *ctx, uint8_t *out, size_t outlen)
{
    shake_update(&ctx->shake, right_encode_zero, sizeof(right_encode_zero));
    shake_custom_final(&ctx->shake, 0x04);
    shake_squeeze(&ctx->shake, out, outlen);
}

int kmacxof256_compute(const uint8_t *key,    size_t klen,
                       const uint8_t *data,   size_t dlen,
                       const uint8_t *custom, size_t clen,
                       uint8_t *out, size_t outlen)
{
    if (!out || outlen == 0) return -1;
    KMACXOF256_CTX ctx;
    kmacxof256_init(&ctx, key, klen, custom, clen);
    kmacxof256_update(&ctx, data, dlen);
    kmacxof256_final(&ctx, out, outlen);
    return 0;
}

void kmacxof256_ops_init_fn(KMACXOF256_CTX *ctx)
{
    kmacxof256_init(ctx, NULL, 0, NULL, 0);
}
