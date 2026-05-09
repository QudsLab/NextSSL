/* aes_pmac.c — AES-PMAC (Rogaway 2000)
 *
 * Simplified sequential PMAC (the streaming interface processes blocks
 * sequentially; parallel mode requires caller-level threading).
 *
 * Algorithm (PMAC-1):
 *   L = E_K(0^128)
 *   L[i] = x^i * L in GF(2^128), irreducible poly x^128+x^7+x^2+x+1
 *   Offset[i] = L[ntz(i)]  (ntz = number of trailing zeros)
 *   For full blocks i=1..m-1: Z_i = M_i XOR Offset[i]; sum ^= E_K(Z_i)
 *   For the last block:
 *     If |M_m| == n: sum ^= E_K(M_m XOR Offset[m] XOR L[-1])
 *     Else:          sum ^= E_K(pad(M_m) XOR Offset[m] XOR L[-2])
 *   Tag = E_K(sum)
 *
 * Here L[-1] = L/x  (multiply by x^{-1}) and L[-2] = x * L[-1].
 */
#include "aes_pmac.h"
#include "../../symmetric/_aes/aes_core.h"
#include <string.h>

static void aes_ecb(const uint8_t *key, size_t keylen,
                    const uint8_t in[16], uint8_t out[16])
{
    aes_ecb_encrypt_block(key, (int)(keylen * 8), in, out);
}

static void xor16(uint8_t *dst, const uint8_t *src)
{
    for (int i = 0; i < 16; i++) dst[i] ^= src[i];
}

/* GF(2^128) multiply by x (left shift + conditional XOR 0x87) */
static void gf128_mul2(const uint8_t in[16], uint8_t out[16])
{
    uint8_t carry = in[0] >> 7;
    for (int i = 0; i < 15; i++)
        out[i] = (uint8_t)((in[i] << 1) | (in[i+1] >> 7));
    out[15] = (uint8_t)(in[15] << 1);
    if (carry) out[15] ^= 0x87;
}

/* GF(2^128) divide by x (right shift + conditional XOR at MSB) */
static void gf128_div2(const uint8_t in[16], uint8_t out[16])
{
    uint8_t carry = in[15] & 1;
    for (int i = 15; i > 0; i--)
        out[i] = (uint8_t)((in[i] >> 1) | (in[i-1] << 7));
    out[0] = (uint8_t)(in[0] >> 1);
    if (carry) out[0] ^= 0x80, out[15] ^= 0x43;
}

/* Number of trailing zero bits in i (ntz) */
static int ntz(size_t i)
{
    if (i == 0) return 64;
    int n = 0;
    while ((i & 1) == 0) { n++; i >>= 1; }
    return n;
}

/* Precompute L[i] = 2^i * L up to index 64 */
#define PMAC_MAX_L 65

int pmac_init(pmac_ctx *ctx, const uint8_t *key, size_t keylen)
{
    if (!ctx || !key) return -1;
    if (keylen != 16 && keylen != 24 && keylen != 32) return -1;
    memcpy(ctx->key, key, keylen);
    ctx->keylen = keylen;

    /* L = E_K(0) */
    uint8_t zero[16] = {0};
    aes_ecb(key, keylen, zero, ctx->L);

    memcpy(ctx->Lx, ctx->L, 16);  /* Lx starts as L; mul2 per block */
    memset(ctx->sum, 0, 16);
    memset(ctx->buf, 0, 16);
    ctx->buf_len     = 0;
    ctx->block_count = 0;
    return 0;
}

/* Get L[ntz(i)] where L[1]=L, L[2]=2L, L[3]=4L, ...
 * We compute on the fly. */
static void get_L_ntz(pmac_ctx *ctx, size_t block_idx, uint8_t out[16])
{
    /* L[ntz(block_idx)] */
    int n = ntz(block_idx);
    uint8_t tmp[16];
    memcpy(tmp, ctx->L, 16);
    for (int i = 1; i <= n; i++) {
        uint8_t t2[16];
        gf128_mul2(tmp, t2);
        memcpy(tmp, t2, 16);
    }
    memcpy(out, tmp, 16);
}

int pmac_update(pmac_ctx *ctx, const uint8_t *data, size_t len)
{
    if (!ctx || (!data && len)) return -1;

    const uint8_t *p = data;
    size_t rem = len;

    if (ctx->buf_len > 0) {
        size_t take = 16 - ctx->buf_len;
        if (take > rem) take = rem;
        memcpy(ctx->buf + ctx->buf_len, p, take);
        ctx->buf_len += take;
        p += take; rem -= take;

        if (ctx->buf_len == 16 && rem > 0) {
            ctx->block_count++;
            uint8_t Li[16];
            get_L_ntz(ctx, ctx->block_count, Li);
            uint8_t Z[16];
            memcpy(Z, ctx->buf, 16);
            xor16(Z, Li);
            uint8_t tmp[16];
            aes_ecb(ctx->key, ctx->keylen, Z, tmp);
            xor16(ctx->sum, tmp);
            ctx->buf_len = 0;
        }
    }

    while (rem > 16) {
        ctx->block_count++;
        uint8_t Li[16];
        get_L_ntz(ctx, ctx->block_count, Li);
        uint8_t Z[16];
        memcpy(Z, p, 16);
        xor16(Z, Li);
        uint8_t tmp[16];
        aes_ecb(ctx->key, ctx->keylen, Z, tmp);
        xor16(ctx->sum, tmp);
        p += 16; rem -= 16;
    }

    if (rem > 0) {
        memcpy(ctx->buf + ctx->buf_len, p, rem);
        ctx->buf_len += rem;
    }
    return 0;
}

int pmac_final(pmac_ctx *ctx, uint8_t tag[PMAC_TAG_SIZE])
{
    if (!ctx || !tag) return -1;

    ctx->block_count++;
    uint8_t Li[16];
    get_L_ntz(ctx, ctx->block_count, Li);

    /* L[-1] = L / x */
    uint8_t Linv[16], Linv2[16];
    gf128_div2(ctx->L, Linv);
    gf128_mul2(Linv, Linv2);  /* L[-2] = 2 * L[-1] */

    uint8_t Z[16];
    if (ctx->buf_len == 16) {
        /* Full final block: Z = M_m XOR L[ntz(m)] XOR L[-1] */
        memcpy(Z, ctx->buf, 16);
        xor16(Z, Li);
        xor16(Z, Linv);
    } else {
        /* Short block: pad with 1||0*, Z = M_m* XOR L[ntz(m)] XOR L[-2] */
        memcpy(Z, ctx->buf, ctx->buf_len);
        Z[ctx->buf_len] = 0x80;
        memset(Z + ctx->buf_len + 1, 0, 16 - ctx->buf_len - 1);
        xor16(Z, Li);
        xor16(Z, Linv2);
    }

    uint8_t tmp[16];
    aes_ecb(ctx->key, ctx->keylen, Z, tmp);
    xor16(ctx->sum, tmp);
    aes_ecb(ctx->key, ctx->keylen, ctx->sum, tag);

    memset(ctx, 0, sizeof(*ctx));
    return 0;
}

int aes_pmac(const uint8_t *key,  size_t keylen,
             const uint8_t *msg,  size_t msglen,
             uint8_t        tag[PMAC_TAG_SIZE])
{
    pmac_ctx ctx;
    if (pmac_init(&ctx, key, keylen)         != 0) return -1;
    if (pmac_update(&ctx, msg, msglen)       != 0) return -1;
    return pmac_final(&ctx, tag);
}
