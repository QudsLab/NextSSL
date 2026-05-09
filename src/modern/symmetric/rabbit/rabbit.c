/* rabbit.c — Rabbit stream cipher (RFC 4503) */
#include "rabbit.h"
#include <string.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32-(n))))

static uint32_t load32_le(const uint8_t *b)
{
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

/* g(u,v) = (u+v)^2 XOR ((u+v)^2 >> 16), low 32 bits then high 16 concat */
static uint32_t g_func(uint32_t u, uint32_t v)
{
    uint64_t uv = (uint64_t)(u + v);
    uint64_t sq = uv * uv;
    return (uint32_t)sq ^ (uint32_t)(sq >> 32);
}

/* Counter values (A array from spec §2.5) */
static const uint32_t A[8] = {
    0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D,
    0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3
};

static void next_state(rabbit_ctx *ctx)
{
    uint32_t g[8];
    int i;

    /* Counter update */
    uint32_t carry = ctx->carry;
    for (i = 0; i < 8; i++) {
        uint64_t t = (uint64_t)ctx->c[i] + A[i] + carry;
        ctx->c[i] = (uint32_t)t;
        carry = (uint32_t)(t >> 32);
    }
    ctx->carry = carry;

    /* Next state */
    for (i = 0; i < 8; i++)
        g[i] = g_func(ctx->x[i], ctx->c[i]);

    ctx->x[0] = g[0] + ROTL32(g[7], 16) + ROTL32(g[6], 16);
    ctx->x[1] = g[1] + ROTL32(g[0],  8) + g[7];
    ctx->x[2] = g[2] + ROTL32(g[1], 16) + ROTL32(g[0], 16);
    ctx->x[3] = g[3] + ROTL32(g[2],  8) + g[1];
    ctx->x[4] = g[4] + ROTL32(g[3], 16) + ROTL32(g[2], 16);
    ctx->x[5] = g[5] + ROTL32(g[4],  8) + g[3];
    ctx->x[6] = g[6] + ROTL32(g[5], 16) + ROTL32(g[4], 16);
    ctx->x[7] = g[7] + ROTL32(g[6],  8) + g[5];
}

int rabbit_init(rabbit_ctx *ctx, const uint8_t key[RABBIT_KEY_SIZE])
{
    if (!ctx || !key) return -1;
    int i;
    /* Load key into state */
    for (i = 0; i < 4; i++) {
        ctx->x[2*i]   = load32_le(key + 4*i);
        ctx->x[2*i+1] = load32_le(key + 4*i + 2); /* shifted by 2 for x_{2i+1} */
    }
    /* Actually: x_j = key bits per spec §2.3 */
    ctx->x[0] = load32_le(key +  0);
    ctx->x[1] = (load32_le(key + 6) << 16) | (load32_le(key + 4) >> 16);
    ctx->x[2] = load32_le(key +  8);
    ctx->x[3] = (load32_le(key + 14) << 16) | (load32_le(key + 12) >> 16);
    ctx->x[4] = load32_le(key +  4);
    ctx->x[5] = (load32_le(key + 10) << 16) | (load32_le(key + 8) >> 16);
    ctx->x[6] = load32_le(key + 12);
    ctx->x[7] = (load32_le(key + 2)  << 16) | (load32_le(key + 0) >> 16);
    /* Counter setup */
    for (i = 0; i < 8; i++) {
        ctx->c[i & 1 ? (i + 4) & 7 : i] = ctx->x[(i + 4) & 7];
    }
    ctx->c[0] = ctx->x[4]; ctx->c[1] = ctx->x[5];
    ctx->c[2] = ctx->x[6]; ctx->c[3] = ctx->x[7];
    ctx->c[4] = ctx->x[0]; ctx->c[5] = ctx->x[1];
    ctx->c[6] = ctx->x[2]; ctx->c[7] = ctx->x[3];
    ctx->carry = 0;

    /* 4 initial iterations */
    for (i = 0; i < 4; i++) next_state(ctx);

    /* Re-key counters */
    for (i = 0; i < 8; i++) ctx->c[i] ^= ctx->x[(i + 4) & 7];
    return 0;
}

void rabbit_set_iv(rabbit_ctx *ctx, const uint8_t iv[RABBIT_IV_SIZE])
{
    if (!ctx || !iv) return;
    uint32_t i0 = load32_le(iv + 0);
    uint32_t i1 = load32_le(iv + 4);
    ctx->c[0] ^= i0;
    ctx->c[2] ^= i1;
    ctx->c[4] ^= i0;
    ctx->c[6] ^= i1;
    ctx->c[1] ^= (i0 >> 16) | (i1 << 16);
    ctx->c[3] ^= (i1 >> 16) | (i0 << 16);
    ctx->c[5] ^= (i0 >> 16) | (i1 << 16);
    ctx->c[7] ^= (i1 >> 16) | (i0 << 16);
    for (int i = 0; i < 4; i++) next_state(ctx);
}

void rabbit_keystream(rabbit_ctx *ctx, uint8_t *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        next_state(ctx);
        /* Output block: XOR of x values */
        uint32_t s[4];
        s[0] = ctx->x[0] ^ (ctx->x[5] >> 16) ^ (ctx->x[3] << 16);
        s[1] = ctx->x[2] ^ (ctx->x[7] >> 16) ^ (ctx->x[5] << 16);
        s[2] = ctx->x[4] ^ (ctx->x[1] >> 16) ^ (ctx->x[7] << 16);
        s[3] = ctx->x[6] ^ (ctx->x[3] >> 16) ^ (ctx->x[1] << 16);

        uint8_t block[16];
        for (int i = 0; i < 4; i++) {
            block[i*4+0] = (uint8_t)(s[i]);
            block[i*4+1] = (uint8_t)(s[i] >>  8);
            block[i*4+2] = (uint8_t)(s[i] >> 16);
            block[i*4+3] = (uint8_t)(s[i] >> 24);
        }
        size_t take = (len - done < 16) ? (len - done) : 16;
        memcpy(buf + done, block, take);
        done += take;
    }
}

void rabbit_xor(rabbit_ctx *ctx,
                 const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t ks[64];
    size_t done = 0;
    while (done < len) {
        size_t chunk = (len - done < 64) ? (len - done) : 64;
        rabbit_keystream(ctx, ks, chunk);
        for (size_t i = 0; i < chunk; i++) out[done + i] = in[done + i] ^ ks[i];
        done += chunk;
    }
}
