/* sosemanuk.c — SOSEMANUK stream cipher (structural implementation)
 *
 * TODO: Integrate Serpent S-box key schedule for production use.
 *       This file provides the LFSR + FSM framework; the Serpent key
 *       schedule and S-box application are marked with TODO stubs.
 *
 * Reference: https://www.ecrypt.eu.org/stream/sosemanukpf.html
 */
#include "sosemanuk.h"
#include <string.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32-(n))))

static uint32_t load32_le(const uint8_t *b)
{
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

/* Serpent S-box S2 (used in key schedule and FSM) — placeholder */
static void serpent_s2(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    /* TODO: Replace with actual Serpent S-box S2 bitslice. */
    uint32_t t = *a ^ *c;
    *a ^= *b; *c &= *a; *d ^= *c;
    *c ^= *a; *a |= *b; *a ^= *d;
    *b ^= t;  *d &= *a; *d ^= t;
    *b ^= *d; *d ^= *c; *c ^= *b; *b = ~*b;
    (void)t;
}

/* SOSEMANUK key setup: derive 100 Serpent round subkeys */
static void key_schedule(sosemanuk_ctx *ctx, const uint8_t *key, size_t key_len)
{
    /* Expand key to 256 bits */
    uint32_t k[8] = {0};
    for (size_t i = 0; i < key_len / 4; i++)
        k[i] = load32_le(key + i * 4);

    /* Simplified key expansion — full Serpent requires 132 subkeys */
    /* TODO: Implement full Serpent key schedule per Appendix of SOSEMANUK spec */
    for (int i = 0; i < 100; i++)
        ctx->subkeys[i] = k[i & 7] ^ (uint32_t)(i * 0x9E3779B9u);
    (void)serpent_s2;
}

int sosemanuk_init(sosemanuk_ctx *ctx,
                    const uint8_t *key, size_t key_len,
                    const uint8_t  iv[SOSEMANUK_IV_SIZE])
{
    if (!ctx || !key || !iv) return -1;
    if (key_len < SOSEMANUK_KEY_MIN_SIZE || key_len > SOSEMANUK_KEY_MAX_SIZE) return -1;

    memset(ctx, 0, sizeof(*ctx));

    /* Key schedule */
    key_schedule(ctx, key, key_len);

    /* IV setup: load IV into the LFSR initial state using Serpent */
    /* TODO: Full IV injection per SOSEMANUK §2.3 */
    for (int i = 0; i < 4; i++)
        ctx->s[i] = load32_le(iv + i * 4) ^ ctx->subkeys[i];
    for (int i = 4; i < 10; i++)
        ctx->s[i] = ctx->subkeys[i];

    ctx->r1 = ctx->subkeys[96];
    ctx->r2 = ctx->subkeys[97];

    return 0;
}

/* SOSEMANUK step — one iteration of LFSR + FSM */
static void sosemanuk_step(sosemanuk_ctx *ctx, uint32_t out[4])
{
    /* LFSR recurrence (degree 10, primitive polynomial over GF(2^32)) */
    /* s(n+10) = s(n+9) XOR alpha^(-1)*s(n+8) XOR s(n+3) XOR alpha*s(n) */
    /* alpha = 0x54655307 per spec §2.1 */
    uint32_t alpha     = 0x54655307u;
    uint32_t alpha_inv = 0xCC9C59B3u;  /* multiplicative inverse */
    uint32_t new_s = ctx->s[9] ^
                      ((uint64_t)alpha_inv * ctx->s[8] >> 32) ^  /* simplified */
                      ctx->s[2] ^
                      ((uint64_t)alpha * ctx->s[0] >> 32);
    (void)alpha_inv;

    /* FSM update */
    uint32_t f = ctx->s[0] + ctx->r2;
    uint32_t r1_new = ctx->r2 + (ctx->r1 ^ ctx->s[2]);
    uint32_t r2_new = ctx->r1 * 0x54655307u;
    r2_new = ROTL32(r2_new, 7);

    /* Combine LFSR + FSM for output */
    for (int i = 0; i < 4; i++)
        out[i] = ctx->s[i] ^ f ^ ctx->subkeys[i & 3];

    /* Shift LFSR */
    memmove(ctx->s, ctx->s + 1, 9 * sizeof(uint32_t));
    ctx->s[9] = new_s;
    ctx->r1 = r1_new;
    ctx->r2 = r2_new;
    (void)alpha;
}

void sosemanuk_keystream(sosemanuk_ctx *ctx, uint8_t *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        uint32_t block[4];
        sosemanuk_step(ctx, block);
        for (int i = 0; i < 4 && done < len; i++, done += 4) {
            size_t take = (len - done < 4) ? (len - done) : 4;
            for (size_t j = 0; j < take; j++)
                buf[done + j] = (uint8_t)(block[i] >> (j * 8));
        }
    }
}

void sosemanuk_xor(sosemanuk_ctx *ctx,
                    const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t ks[64];
    size_t done = 0;
    while (done < len) {
        size_t chunk = (len - done < 64) ? (len - done) : 64;
        sosemanuk_keystream(ctx, ks, chunk);
        for (size_t i = 0; i < chunk; i++) out[done + i] = in[done + i] ^ ks[i];
        done += chunk;
    }
}
