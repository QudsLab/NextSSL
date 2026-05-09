/* turboshake.c — TurboSHAKE: KeccakP-1600 with reduced rounds
 *
 * Implements KeccakP-1600-n where n is 12 (KangarooTwelve) or 14
 * (MarsupilamiFourteen).  The round constants and step mappings are
 * identical to full Keccak-f[1600]; only the round count differs.
 *
 * Derived from the public-domain Keccak reference implementation.
 * This file is original work for NextSSL; no copyrighted code is copied.
 */
#include "turboshake.h"
#include <string.h>

/* =========================================================================
 * KeccakP-1600 round constants (all 24 — we iterate only the first n)
 * ========================================================================= */
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static const uint64_t keccak_rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

/* For TurboSHAKE, only the LAST (24-rounds) rounds are applied.
 * K12 uses the last 12 rounds, M14 uses the last 14 rounds.
 * See RFC 9285 §2.1: "KeccakP-1600-n applies the last n rounds of Keccak-f". */
static void keccakp_1600_n(uint64_t *state, int rounds)
{
    int start = 24 - rounds;
    for (int r = start; r < 24; r++) {
        /* Theta */
        uint64_t C[5], D[5];
        for (int i = 0; i < 5; i++)
            C[i] = state[i] ^ state[i+5] ^ state[i+10] ^ state[i+15] ^ state[i+20];
        for (int i = 0; i < 5; i++)
            D[i] = C[(i+4)%5] ^ ROTL64(C[(i+1)%5], 1);
        for (int i = 0; i < 25; i++)
            state[i] ^= D[i%5];

        /* Rho + Pi combined */
        static const int rho_off[25] = {
            0, 1, 62, 28, 27,
            36, 44, 6, 55, 20,
            3, 10, 43, 25, 39,
            41, 45, 15, 21, 8,
            18, 2, 61, 56, 14
        };
        static const int pi_idx[25] = {
            0, 10, 20, 5, 15,
            16, 1, 11, 21, 6,
            7, 17, 2, 12, 22,
            23, 8, 18, 3, 13,
            14, 24, 9, 19, 4
        };
        uint64_t tmp[25];
        for (int i = 0; i < 25; i++)
            tmp[pi_idx[i]] = ROTL64(state[i], rho_off[i]);

        /* Chi */
        for (int y = 0; y < 25; y += 5) {
            uint64_t b0 = tmp[y+0], b1 = tmp[y+1], b2 = tmp[y+2],
                     b3 = tmp[y+3], b4 = tmp[y+4];
            state[y+0] = b0 ^ ((~b1) & b2);
            state[y+1] = b1 ^ ((~b2) & b3);
            state[y+2] = b2 ^ ((~b3) & b4);
            state[y+3] = b3 ^ ((~b4) & b0);
            state[y+4] = b4 ^ ((~b0) & b1);
        }

        /* Iota */
        state[0] ^= keccak_rc[r];
    }
}

/* =========================================================================
 * Sponge helpers
 * ========================================================================= */
static void absorb_block(TURBOSHAKE_CTX *ctx)
{
    size_t lanes = ctx->rate / 8;
    for (size_t j = 0; j < lanes; j++) {
        uint64_t lane = 0;
        for (int k = 0; k < 8; k++)
            lane |= (uint64_t)ctx->buf[j*8 + k] << (8*k);
        ctx->state[j] ^= lane;
    }
    keccakp_1600_n(ctx->state, ctx->rounds);
    ctx->buf_len = 0;
}

/* =========================================================================
 * Public API
 * ========================================================================= */
void turboshake_init(TURBOSHAKE_CTX *ctx, size_t rate, int rounds)
{
    memset(ctx->state, 0, sizeof(ctx->state));
    ctx->rate      = rate;
    ctx->buf_len   = 0;
    ctx->finalized = 0;
    ctx->rounds    = rounds;
    memset(ctx->buf, 0, sizeof(ctx->buf));
}

void turboshake_update(TURBOSHAKE_CTX *ctx, const uint8_t *data, size_t len)
{
    size_t i = 0;
    while (i < len) {
        size_t room = ctx->rate - ctx->buf_len;
        size_t copy = len - i < room ? len - i : room;
        memcpy(ctx->buf + ctx->buf_len, data + i, copy);
        ctx->buf_len += copy;
        i += copy;
        if (ctx->buf_len == ctx->rate)
            absorb_block(ctx);
    }
}

void turboshake_final(TURBOSHAKE_CTX *ctx, uint8_t domain_sep)
{
    /* Pad: domain_sep byte at buf_len, then 0x80 at rate-1 */
    memset(ctx->buf + ctx->buf_len, 0, ctx->rate - ctx->buf_len);
    ctx->buf[ctx->buf_len]   = domain_sep;
    ctx->buf[ctx->rate - 1] |= 0x80;

    size_t lanes = ctx->rate / 8;
    for (size_t j = 0; j < lanes; j++) {
        uint64_t lane = 0;
        for (int k = 0; k < 8; k++)
            lane |= (uint64_t)ctx->buf[j*8 + k] << (8*k);
        ctx->state[j] ^= lane;
    }
    keccakp_1600_n(ctx->state, ctx->rounds);
    ctx->buf_len   = 0;
    ctx->finalized = 1;
}

void turboshake_squeeze(TURBOSHAKE_CTX *ctx, uint8_t *out, size_t outlen)
{
    size_t out_pos = 0;
    while (out_pos < outlen) {
        /* Extract bytes from state in lane order */
        size_t state_bytes = 200; /* 25 * 8 */
        for (size_t i = 0; i < state_bytes && out_pos < outlen; i++) {
            out[out_pos++] = (uint8_t)(ctx->state[i/8] >> (8*(i%8)));
        }
        if (out_pos < outlen) {
            /* need more: squeeze another block */
            keccakp_1600_n(ctx->state, ctx->rounds);
        }
    }
}

void turboshake128_oneshot(const uint8_t *data, size_t dlen,
                           uint8_t domain_sep,
                           uint8_t *out, size_t outlen)
{
    TURBOSHAKE_CTX ctx;
    turboshake_init(&ctx, 168, 12);  /* rate=168, 12 rounds */
    turboshake_update(&ctx, data, dlen);
    turboshake_final(&ctx, domain_sep);
    turboshake_squeeze(&ctx, out, outlen);
}

void turboshake256_oneshot(const uint8_t *data, size_t dlen,
                           uint8_t domain_sep,
                           uint8_t *out, size_t outlen)
{
    TURBOSHAKE_CTX ctx;
    turboshake_init(&ctx, 136, 14);  /* rate=136, 14 rounds */
    turboshake_update(&ctx, data, dlen);
    turboshake_final(&ctx, domain_sep);
    turboshake_squeeze(&ctx, out, outlen);
}
