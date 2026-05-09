/* xcbc_mac.c — AES-XCBC-MAC (RFC 3566)
 *
 * RFC 3566 §3 key schedule:
 *   K1 = E_K(0x01010101...01)
 *   K2 = E_K(0x02020202...02)
 *   K3 = E_K(0x03030303...03)
 *
 * MAC computation:
 *   E0 = 0^128
 *   For full blocks i = 1..n-1: E_i = E_K1(E_{i-1} XOR M_i)
 *   Final block handling:
 *     - Exact multiple: E_n = E_K1(E_{n-1} XOR M_n XOR K2)
 *     - Short final block: pad with 1||0*; E_n = E_K1(E_{n-1} XOR M_n* XOR K3)
 *   MAC = E_n
 */
#include "xcbc_mac.h"
#include "../../symmetric/_aes/aes_core.h"
#include <string.h>

/* AES-128 ECB encrypt one block */
static void aes128_ecb(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    aes_ecb_encrypt_block(key, 128, in, out);
}

/* XOR 16 bytes: dst[i] ^= src[i] */
static void xor16(uint8_t *dst, const uint8_t *src)
{
    for (int i = 0; i < 16; i++) dst[i] ^= src[i];
}

/* Derive sub-keys K1, K2, K3 */
static void derive_subkeys(const uint8_t key[16],
                            uint8_t k1[16], uint8_t k2[16], uint8_t k3[16])
{
    uint8_t c1[16], c2[16], c3[16];
    memset(c1, 0x01, 16); memset(c2, 0x02, 16); memset(c3, 0x03, 16);
    aes128_ecb(key, c1, k1);
    aes128_ecb(key, c2, k2);
    aes128_ecb(key, c3, k3);
}

int xcbc_mac_init(xcbc_mac_ctx *ctx, const uint8_t key[XCBC_MAC_KEY_SIZE])
{
    if (!ctx || !key) return -1;
    derive_subkeys(key, ctx->k1, ctx->k2, ctx->k3);
    memset(ctx->e, 0, 16);
    memset(ctx->buf, 0, 16);
    ctx->buf_len  = 0;
    ctx->has_data = 0;
    return 0;
}

int xcbc_mac_update(xcbc_mac_ctx *ctx, const uint8_t *data, size_t len)
{
    if (!ctx || (!data && len)) return -1;

    const uint8_t *p = data;
    size_t remaining = len;

    /* Fill any partial block first */
    if (ctx->buf_len > 0) {
        size_t take = 16 - ctx->buf_len;
        if (take > remaining) take = remaining;
        memcpy(ctx->buf + ctx->buf_len, p, take);
        ctx->buf_len += take;
        p += take;
        remaining -= take;

        if (ctx->buf_len == 16 && remaining > 0) {
            /* Complete full block — process it (but hold if it's the last) */
            uint8_t tmp[16];
            memcpy(tmp, ctx->e, 16);
            xor16(tmp, ctx->buf);
            aes128_ecb(ctx->k1, tmp, ctx->e);
            ctx->buf_len = 0;
            ctx->has_data = 1;
        }
    }

    /* Process all full blocks except the last one */
    while (remaining > 16) {
        uint8_t tmp[16];
        memcpy(tmp, ctx->e, 16);
        xor16(tmp, p);
        aes128_ecb(ctx->k1, tmp, ctx->e);
        ctx->has_data = 1;
        p += 16;
        remaining -= 16;
    }

    /* Buffer remaining bytes (0–16) as potential final block */
    if (remaining > 0) {
        memcpy(ctx->buf + ctx->buf_len, p, remaining);
        ctx->buf_len += remaining;
    }

    return 0;
}

int xcbc_mac_final(xcbc_mac_ctx *ctx, uint8_t tag[XCBC_MAC_TAG_SIZE])
{
    if (!ctx || !tag) return -1;

    uint8_t tmp[16];
    memcpy(tmp, ctx->e, 16);

    if (ctx->buf_len == 16) {
        /* Final block is exactly 16 bytes: XOR with K2 */
        xor16(tmp, ctx->buf);
        xor16(tmp, ctx->k2);
    } else {
        /* Short final block: apply 10* padding, XOR with K3 */
        uint8_t padded[16];
        memcpy(padded, ctx->buf, ctx->buf_len);
        padded[ctx->buf_len] = 0x80;
        memset(padded + ctx->buf_len + 1, 0, 16 - ctx->buf_len - 1);
        xor16(tmp, padded);
        xor16(tmp, ctx->k3);
    }

    aes128_ecb(ctx->k1, tmp, tag);

    /* Wipe sensitive state */
    memset(ctx, 0, sizeof(*ctx));
    return 0;
}

int xcbc_mac(const uint8_t key[XCBC_MAC_KEY_SIZE],
             const uint8_t *data, size_t len,
             uint8_t        tag[XCBC_MAC_TAG_SIZE])
{
    xcbc_mac_ctx ctx;
    if (xcbc_mac_init(&ctx, key)           != 0) return -1;
    if (xcbc_mac_update(&ctx, data, len)   != 0) return -1;
    return xcbc_mac_final(&ctx, tag);
}
