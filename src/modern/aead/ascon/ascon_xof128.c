/* ascon_xof128.c — Ascon-XOF128 (SP 800-232) */
#include "ascon_xof128.h"
#include "ascon_core.h"
#include <string.h>

#define PA  12
#define PB   8
#define RATE 8

#define ASCON_XOF128_IV 0x00400c0000000000ULL

void ascon_xof128_init(ascon_xof128_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->x[0] = ASCON_XOF128_IV;
    ascon_state_t s; memcpy(s.x, ctx->x, 40);
    ascon_permute(&s, PA);
    memcpy(ctx->x, s.x, 40);
}

void ascon_xof128_absorb(ascon_xof128_ctx_t *ctx, const uint8_t *in, size_t inlen)
{
    ascon_state_t s; memcpy(s.x, ctx->x, 40);

    /* Fill partial buffer first */
    while (ctx->buf_len > 0 && inlen > 0) {
        ctx->buf[ctx->buf_len++] = *in++;
        inlen--;
        if (ctx->buf_len == RATE) {
            s.x[0] ^= ascon_load64(ctx->buf);
            ascon_permute(&s, PB);
            ctx->buf_len = 0;
        }
    }
    while (inlen >= RATE) {
        s.x[0] ^= ascon_load64(in);
        ascon_permute(&s, PB);
        in += RATE; inlen -= RATE;
    }
    memcpy(ctx->buf + ctx->buf_len, in, inlen);
    ctx->buf_len += inlen;
    memcpy(ctx->x, s.x, 40);
}

void ascon_xof128_squeeze(ascon_xof128_ctx_t *ctx, uint8_t *out, size_t outlen)
{
    ascon_state_t s; memcpy(s.x, ctx->x, 40);

    if (!ctx->squeezing) {
        /* Finalize absorb */
        uint8_t buf[RATE] = {0};
        memcpy(buf, ctx->buf, ctx->buf_len);
        buf[ctx->buf_len] = 0x80;
        s.x[0] ^= ascon_load64(buf);
        ascon_permute(&s, PA);
        ctx->squeezing = 1;
    }

    while (outlen >= RATE) {
        ascon_store64(out, s.x[0]);
        ascon_permute(&s, PB);
        out += RATE; outlen -= RATE;
    }
    if (outlen > 0) {
        uint8_t tmp[RATE];
        ascon_store64(tmp, s.x[0]);
        memcpy(out, tmp, outlen);
    }
    memcpy(ctx->x, s.x, 40);
}

void ascon_xof128(const uint8_t *msg, size_t msglen, uint8_t *out, size_t outlen)
{
    ascon_xof128_ctx_t ctx;
    ascon_xof128_init(&ctx);
    ascon_xof128_absorb(&ctx, msg, msglen);
    ascon_xof128_squeeze(&ctx, out, outlen);
}
