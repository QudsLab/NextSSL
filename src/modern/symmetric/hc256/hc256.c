/* hc256.c — HC-256 stream cipher */
#include "hc256.h"
#include <string.h>

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32-(n))))

#define f1(x) (ROTR32(x, 7) ^ ROTR32(x,18) ^ ((x) >> 3))
#define f2(x) (ROTR32(x,17) ^ ROTR32(x,19) ^ ((x) >> 10))
#define g1(ctx, x, y) (ROTR32(x, 10) ^ ROTR32(y, 23)) + (ctx)->Q[((x)^(y))&0x3FF]
#define g2(ctx, x, y) (ROTR32(x, 10) ^ ROTR32(y, 23)) + (ctx)->P[((x)^(y))&0x3FF]

static uint32_t h1_256(const hc256_ctx *ctx, uint32_t x)
{
    return ctx->Q[(uint8_t)(x)] +
           ctx->Q[256 + (uint8_t)(x >> 8)] +
           ctx->Q[512 + (uint8_t)(x >> 16)] +
           ctx->Q[768 + (uint8_t)(x >> 24)];
}

static uint32_t h2_256(const hc256_ctx *ctx, uint32_t x)
{
    return ctx->P[(uint8_t)(x)] +
           ctx->P[256 + (uint8_t)(x >> 8)] +
           ctx->P[512 + (uint8_t)(x >> 16)] +
           ctx->P[768 + (uint8_t)(x >> 24)];
}

int hc256_init(hc256_ctx *ctx,
                const uint8_t key[HC256_KEY_SIZE],
                const uint8_t iv[HC256_IV_SIZE])
{
    if (!ctx || !key || !iv) return -1;

    uint32_t W[2560];
    int i;
    /* W[0..7] = key; W[8..15] = IV */
    for (i = 0; i < 8; i++)
        W[i] = (uint32_t)key[i*4] | ((uint32_t)key[i*4+1] << 8) |
               ((uint32_t)key[i*4+2] << 16) | ((uint32_t)key[i*4+3] << 24);
    for (i = 0; i < 8; i++)
        W[8+i] = (uint32_t)iv[i*4] | ((uint32_t)iv[i*4+1] << 8) |
                 ((uint32_t)iv[i*4+2] << 16) | ((uint32_t)iv[i*4+3] << 24);
    for (i = 16; i < 2560; i++)
        W[i] = f2(W[i-2]) + W[i-7] + f1(W[i-15]) + W[i-16] + (uint32_t)i;

    for (i = 0; i < 1024; i++) ctx->P[i] = W[i];
    for (i = 0; i < 1024; i++) ctx->Q[i] = W[i + 1024];

    /* Warm-up: 4096 rounds */
    ctx->cnt = 0;
    uint8_t discard[4096 * 4];
    hc256_keystream(ctx, discard, sizeof(discard));
    ctx->cnt = 0;
    return 0;
}

void hc256_keystream(hc256_ctx *ctx, uint8_t *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        uint32_t s;
        uint32_t j = ctx->cnt & 1023;
        if (ctx->cnt < 1024) {
            ctx->P[j] += ctx->P[(j-10)&1023] +
                g1(ctx, ctx->P[(j-3)&1023], ctx->P[(j-1023)&1023]);
            s = h1_256(ctx, ctx->P[(j-12)&1023]) ^ ctx->P[j];
        } else {
            ctx->Q[j] += ctx->Q[(j-10)&1023] +
                g2(ctx, ctx->Q[(j-3)&1023], ctx->Q[(j-1023)&1023]);
            s = h2_256(ctx, ctx->Q[(j-12)&1023]) ^ ctx->Q[j];
        }
        ctx->cnt = (ctx->cnt + 1) & 2047;

        size_t take = (len - done < 4) ? (len - done) : 4;
        for (size_t k = 0; k < take; k++)
            buf[done + k] = (uint8_t)(s >> (k * 8));
        done += take;
    }
}

void hc256_xor(hc256_ctx *ctx,
                const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t ks[64];
    size_t done = 0;
    while (done < len) {
        size_t chunk = (len - done < 64) ? (len - done) : 64;
        hc256_keystream(ctx, ks, chunk);
        for (size_t i = 0; i < chunk; i++) out[done + i] = in[done + i] ^ ks[i];
        done += chunk;
    }
}
