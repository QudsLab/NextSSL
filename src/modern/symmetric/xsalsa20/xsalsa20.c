/* xsalsa20.c — XSalsa20 using HSalsa20 for key/nonce expansion */
#include "xsalsa20.h"
#include <string.h>

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static uint32_t load32_le(const uint8_t *b)
{
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static void store32_le(uint8_t *b, uint32_t v)
{
    b[0] = (uint8_t)(v);      b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16); b[3] = (uint8_t)(v >> 24);
}

/* HSalsa20: apply 20 rounds but return the 4 "corner" words as subkey */
static void hsalsa20(const uint8_t key[32], const uint8_t nonce16[16],
                      uint8_t subkey[32])
{
    static const uint8_t SIGMA[16] = "expand 32-byte k";
    uint32_t x[16];

    x[ 0] = load32_le(SIGMA +  0);
    x[ 1] = load32_le(key   +  0);
    x[ 2] = load32_le(key   +  4);
    x[ 3] = load32_le(key   +  8);
    x[ 4] = load32_le(key   + 12);
    x[ 5] = load32_le(SIGMA +  4);
    x[ 6] = load32_le(nonce16 + 0);
    x[ 7] = load32_le(nonce16 + 4);
    x[ 8] = load32_le(nonce16 + 8);
    x[ 9] = load32_le(nonce16 +12);
    x[10] = load32_le(SIGMA  + 8);
    x[11] = load32_le(key   + 16);
    x[12] = load32_le(key   + 20);
    x[13] = load32_le(key   + 24);
    x[14] = load32_le(key   + 28);
    x[15] = load32_le(SIGMA + 12);

#define QR(a,b,c,d) \
    b ^= ROTL32(a+d, 7); \
    c ^= ROTL32(b+a, 9); \
    d ^= ROTL32(c+b,13); \
    a ^= ROTL32(d+c,18);

    for (int i = 0; i < 10; i++) {
        QR(x[ 0], x[ 4], x[ 8], x[12]);
        QR(x[ 5], x[ 9], x[13], x[ 1]);
        QR(x[10], x[14], x[ 2], x[ 6]);
        QR(x[15], x[ 3], x[ 7], x[11]);
        QR(x[ 0], x[ 1], x[ 2], x[ 3]);
        QR(x[ 5], x[ 6], x[ 7], x[ 4]);
        QR(x[10], x[11], x[ 8], x[ 9]);
        QR(x[15], x[12], x[13], x[14]);
    }
#undef QR

    /* HSalsa20 output: x[0], x[5], x[10], x[15], x[6], x[7], x[8], x[9] */
    store32_le(subkey +  0, x[ 0]);
    store32_le(subkey +  4, x[ 5]);
    store32_le(subkey +  8, x[10]);
    store32_le(subkey + 12, x[15]);
    store32_le(subkey + 16, x[ 6]);
    store32_le(subkey + 20, x[ 7]);
    store32_le(subkey + 24, x[ 8]);
    store32_le(subkey + 28, x[ 9]);
}

int xsalsa20_init(xsalsa20_ctx  *ctx,
                   const uint8_t  key[XSALSA20_KEY_SIZE],
                   const uint8_t  nonce[XSALSA20_NONCE_SIZE])
{
    if (!ctx || !key || !nonce) return -1;

    /* subkey = HSalsa20(key, nonce[0:16]) */
    uint8_t subkey[32];
    hsalsa20(key, nonce, subkey);

    /* inner Salsa20: key=subkey, nonce=nonce[16:24] */
    return salsa20_init(&ctx->inner, subkey, 32, nonce + 16, 0);
}

void xsalsa20_xor(xsalsa20_ctx *ctx,
                   const uint8_t *in, uint8_t *out, size_t len)
{
    salsa20_xor(&ctx->inner, in, out, len);
}

void xsalsa20_keystream(xsalsa20_ctx *ctx, uint8_t *buf, size_t len)
{
    salsa20_keystream(&ctx->inner, buf, len);
}
