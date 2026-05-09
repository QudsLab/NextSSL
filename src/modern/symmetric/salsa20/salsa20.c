/* salsa20.c — Salsa20 stream cipher implementation */
#include "salsa20.h"
#include <string.h>

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static void salsa20_block(const uint32_t input[16], uint8_t output[64])
{
    uint32_t x[16];
    int i;
    for (i = 0; i < 16; i++) x[i] = input[i];

#define QR(a,b,c,d) \
    b ^= ROTL32(a+d, 7); \
    c ^= ROTL32(b+a, 9); \
    d ^= ROTL32(c+b,13); \
    a ^= ROTL32(d+c,18);

    for (i = 0; i < 10; i++) {
        /* Column quarter-rounds */
        QR(x[ 0], x[ 4], x[ 8], x[12]);
        QR(x[ 5], x[ 9], x[13], x[ 1]);
        QR(x[10], x[14], x[ 2], x[ 6]);
        QR(x[15], x[ 3], x[ 7], x[11]);
        /* Row quarter-rounds */
        QR(x[ 0], x[ 1], x[ 2], x[ 3]);
        QR(x[ 5], x[ 6], x[ 7], x[ 4]);
        QR(x[10], x[11], x[ 8], x[ 9]);
        QR(x[15], x[12], x[13], x[14]);
    }
#undef QR

    for (i = 0; i < 16; i++) {
        uint32_t v = x[i] + input[i];
        output[i*4+0] = (uint8_t)(v);
        output[i*4+1] = (uint8_t)(v >> 8);
        output[i*4+2] = (uint8_t)(v >> 16);
        output[i*4+3] = (uint8_t)(v >> 24);
    }
}

static uint32_t load32_le(const uint8_t *b)
{
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static const uint8_t SIGMA[16] = "expand 32-byte k";
static const uint8_t TAU[16]   = "expand 16-byte k";

int salsa20_init(salsa20_ctx *ctx,
                  const uint8_t *key, size_t key_len,
                  const uint8_t  nonce[SALSA20_NONCE_SIZE],
                  uint64_t       counter)
{
    if (!ctx || !key || !nonce) return -1;
    if (key_len != 16 && key_len != 32) return -1;

    const uint8_t *constants = (key_len == 32) ? SIGMA : TAU;

    ctx->state[ 0] = load32_le(constants + 0);
    ctx->state[ 1] = load32_le(key + 0);
    ctx->state[ 2] = load32_le(key + 4);
    ctx->state[ 3] = load32_le(key + 8);
    ctx->state[ 4] = load32_le(key + 12);
    ctx->state[ 5] = load32_le(constants + 4);
    ctx->state[ 6] = load32_le(nonce + 0);
    ctx->state[ 7] = load32_le(nonce + 4);
    ctx->state[ 8] = (uint32_t)(counter);
    ctx->state[ 9] = (uint32_t)(counter >> 32);
    ctx->state[10] = load32_le(constants + 8);
    if (key_len == 32) {
        ctx->state[11] = load32_le(key + 16);
        ctx->state[12] = load32_le(key + 20);
        ctx->state[13] = load32_le(key + 24);
        ctx->state[14] = load32_le(key + 28);
    } else {
        /* 128-bit key: use key twice */
        ctx->state[11] = load32_le(key + 0);
        ctx->state[12] = load32_le(key + 4);
        ctx->state[13] = load32_le(key + 8);
        ctx->state[14] = load32_le(key + 12);
    }
    ctx->state[15] = load32_le(constants + 12);
    return 0;
}

void salsa20_keystream(salsa20_ctx *ctx, uint8_t *buf, size_t len)
{
    uint8_t block[64];
    size_t done = 0;

    while (done < len) {
        salsa20_block(ctx->state, block);
        /* Increment 64-bit counter (words 8, 9) */
        if (++ctx->state[8] == 0) ctx->state[9]++;

        size_t take = (len - done < 64) ? (len - done) : 64;
        memcpy(buf + done, block, take);
        done += take;
    }
    memset(block, 0, sizeof(block));
}

void salsa20_xor(salsa20_ctx *ctx,
                  const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t block[64];
    size_t done = 0;

    while (done < len) {
        salsa20_block(ctx->state, block);
        if (++ctx->state[8] == 0) ctx->state[9]++;

        size_t take = (len - done < 64) ? (len - done) : 64;
        for (size_t i = 0; i < take; i++) out[done + i] = in[done + i] ^ block[i];
        done += take;
    }
    memset(block, 0, sizeof(block));
}
