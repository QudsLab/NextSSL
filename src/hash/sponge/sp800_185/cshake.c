/* cshake.c — cSHAKE-128 and cSHAKE-256 (NIST SP 800-185 §3) */
#include "cshake.h"
#include <string.h>

/* =========================================================================
 * SP 800-185 encoding primitives (local to this translation unit)
 * ========================================================================= */

static size_t cs_left_encode(uint64_t x, uint8_t *buf)
{
    uint8_t tmp[8];
    size_t n = 0;
    if (x == 0) { buf[0] = 1; buf[1] = 0; return 2; }
    uint64_t v = x;
    while (v) { tmp[n++] = (uint8_t)(v & 0xFF); v >>= 8; }
    buf[0] = (uint8_t)n;
    for (size_t i = 0; i < n; i++) buf[1 + i] = tmp[n - 1 - i];
    return 1 + n;
}

/* Absorb encode_string(s, slen) into sponge.
 * Returns total bytes fed to shake_update (for bytepad tracking). */
static size_t cs_absorb_encode_string(SHAKE_CTX *sh,
                                       const uint8_t *s, size_t slen)
{
    uint8_t enc[9];
    size_t enc_len = cs_left_encode((uint64_t)slen * 8, enc);
    shake_update(sh, enc, enc_len);
    if (slen > 0) shake_update(sh, s, slen);
    return enc_len + slen;
}

/* Zero-pad sponge to next multiple of w after absorbing `absorbed` bytes. */
static void cs_finish_bytepad(SHAKE_CTX *sh, size_t w, size_t absorbed)
{
    size_t pad = w - (absorbed % w);
    if (pad == w) return;
    static const uint8_t zeros[200] = {0};
    while (pad > 0) {
        size_t chunk = pad < sizeof(zeros) ? pad : sizeof(zeros);
        shake_update(sh, zeros, chunk);
        pad -= chunk;
    }
}

/* =========================================================================
 * Common init helper
 * ========================================================================= */

static void cshake_init_common(CSHAKE_CTX *ctx, size_t rate,
                                const uint8_t *N, size_t Nlen,
                                const uint8_t *S, size_t Slen)
{
    memset(&ctx->shake, 0, sizeof(ctx->shake));
    ctx->shake.rate = rate;
    ctx->pure_shake = (Nlen == 0 && Slen == 0) ? 1 : 0;

    if (ctx->pure_shake) return; /* no bytepad prefix when N=S="" */

    /* bytepad(encode_string(N) || encode_string(S), rate) */
    uint8_t w_enc[9];
    size_t  w_len = cs_left_encode((uint64_t)rate, w_enc);
    shake_update(&ctx->shake, w_enc, w_len);
    size_t absorbed = w_len;

    absorbed += cs_absorb_encode_string(&ctx->shake, N, Nlen);
    absorbed += cs_absorb_encode_string(&ctx->shake, S, Slen);

    cs_finish_bytepad(&ctx->shake, rate, absorbed);
}

/* =========================================================================
 * Public API
 * ========================================================================= */

void cshake128_init(CSHAKE_CTX *ctx,
                    const uint8_t *N, size_t Nlen,
                    const uint8_t *S, size_t Slen)
{
    cshake_init_common(ctx, 168, N, Nlen, S, Slen);
}

void cshake256_init(CSHAKE_CTX *ctx,
                    const uint8_t *N, size_t Nlen,
                    const uint8_t *S, size_t Slen)
{
    cshake_init_common(ctx, 136, N, Nlen, S, Slen);
}

void cshake_update(CSHAKE_CTX *ctx, const uint8_t *data, size_t len)
{
    shake_update(&ctx->shake, data, len);
}

void cshake_squeeze(CSHAKE_CTX *ctx, uint8_t *out, size_t outlen)
{
    uint8_t pad = ctx->pure_shake ? 0x1F : 0x04;
    shake_custom_final(&ctx->shake, pad);
    shake_squeeze(&ctx->shake, out, outlen);
}

void cshake128(const uint8_t *N, size_t Nlen,
               const uint8_t *S, size_t Slen,
               const uint8_t *data, size_t dlen,
               uint8_t *out, size_t outlen)
{
    CSHAKE_CTX ctx;
    cshake128_init(&ctx, N, Nlen, S, Slen);
    cshake_update(&ctx, data, dlen);
    cshake_squeeze(&ctx, out, outlen);
}

void cshake256(const uint8_t *N, size_t Nlen,
               const uint8_t *S, size_t Slen,
               const uint8_t *data, size_t dlen,
               uint8_t *out, size_t outlen)
{
    CSHAKE_CTX ctx;
    cshake256_init(&ctx, N, Nlen, S, Slen);
    cshake_update(&ctx, data, dlen);
    cshake_squeeze(&ctx, out, outlen);
}
