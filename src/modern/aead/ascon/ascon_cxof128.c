/* ascon_cxof128.c — Ascon-CXOF128 (SP 800-232)
 *
 * CXOF128 extends XOF128 by absorbing the customization string Z
 * with a different domain separator before the message. */
#include "ascon_cxof128.h"
#include "ascon_core.h"
#include <string.h>

#define PA  12
#define PB   8
#define RATE 8

/* IV for Ascon-CXOF128 (differs from XOF128 in domain byte) */
#define ASCON_CXOF128_IV 0x00400c0000000002ULL

void ascon_cxof128_init(ascon_cxof128_ctx_t *ctx,
                         const uint8_t *Z, size_t Zlen)
{
    ascon_state_t s;
    memset(&s, 0, sizeof(s));
    s.x[0] = ASCON_CXOF128_IV;
    ascon_permute(&s, PA);

    /* Absorb customization string Z with domain separator 0x01 appended */
    const uint8_t *z = Z;
    size_t zlen = Zlen;
    while (zlen >= RATE) {
        s.x[0] ^= ascon_load64(z);
        ascon_permute(&s, PB);
        z += RATE; zlen -= RATE;
    }
    uint8_t buf[RATE] = {0};
    memcpy(buf, z, zlen);
    buf[zlen] = 0x01;  /* customization domain separator */
    s.x[0] ^= ascon_load64(buf);
    ascon_permute(&s, PB);

    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->x, s.x, 40);
}

void ascon_cxof128_absorb(ascon_cxof128_ctx_t *ctx, const uint8_t *in, size_t inlen)
{
    ascon_state_t s; memcpy(s.x, ctx->x, 40);
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

void ascon_cxof128_squeeze(ascon_cxof128_ctx_t *ctx, uint8_t *out, size_t outlen)
{
    ascon_state_t s; memcpy(s.x, ctx->x, 40);
    if (!ctx->squeezing) {
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

void ascon_cxof128(const uint8_t *Z, size_t Zlen,
                   const uint8_t *msg, size_t msglen,
                   uint8_t *out, size_t outlen)
{
    ascon_cxof128_ctx_t ctx;
    ascon_cxof128_init(&ctx, Z, Zlen);
    ascon_cxof128_absorb(&ctx, msg, msglen);
    ascon_cxof128_squeeze(&ctx, out, outlen);
}
