/* tiger.c — Tiger hash implementation
 *
 * Based on "Tiger: A Fast New Hash Function" by Anderson & Biham (1996).
 * S-box tables in tiger_sbox.c (from RHash, BSD Zero Clause License).
 *
 * 192-bit digest, 64-byte block, 3 passes of 8 rounds each.
 */
#include "tiger.h"
#include <string.h>

/* S-box tables defined in tiger_sbox.c */
extern const uint64_t tiger_sboxes[4][256];

#define t1 tiger_sboxes[0]
#define t2 tiger_sboxes[1]
#define t3 tiger_sboxes[2]
#define t4 tiger_sboxes[3]

/* ---- Tiger round function ------------------------------------------- */
static void tiger_round(uint64_t *a, uint64_t *b, uint64_t *c,
                         uint64_t x, uint64_t mul) {
    *c ^= x;
    *a -= t1[(uint8_t)(*c)]              ^ t2[(uint8_t)((*c) >> 16)] ^
          t3[(uint8_t)((*c) >> 32)]       ^ t4[(uint8_t)((*c) >> 48)];
    *b += t4[(uint8_t)((*c) >> 8)]        ^ t3[(uint8_t)((*c) >> 24)] ^
          t2[(uint8_t)((*c) >> 40)]       ^ t1[(uint8_t)((*c) >> 56)];
    *b *= mul;
}

/* ---- Tiger key schedule --------------------------------------------- */
static void tiger_key_schedule(uint64_t x[8]) {
    x[0] -= x[7] ^ 0xA5A5A5A5A5A5A5A5ULL;
    x[1] ^= x[0];
    x[2] += x[1];
    x[3] -= x[2] ^ ((~x[1]) << 19);
    x[4] ^= x[3];
    x[5] += x[4];
    x[6] -= x[5] ^ ((~x[4]) >> 23);
    x[7] ^= x[6];
    x[0] += x[7];
    x[1] -= x[0] ^ ((~x[7]) << 19);
    x[2] ^= x[1];
    x[3] += x[2];
    x[4] -= x[3] ^ ((~x[2]) >> 23);
    x[5] ^= x[4];
    x[6] += x[5];
    x[7] -= x[6] ^ 0x0123456789ABCDEFULL;
}

/* ---- Pass: 8 rounds with given multiplier --------------------------- */
static void tiger_pass(uint64_t *a, uint64_t *b, uint64_t *c,
                        uint64_t x[8], uint64_t mul) {
    tiger_round(a, b, c, x[0], mul);
    tiger_round(b, c, a, x[1], mul);
    tiger_round(c, a, b, x[2], mul);
    tiger_round(a, b, c, x[3], mul);
    tiger_round(b, c, a, x[4], mul);
    tiger_round(c, a, b, x[5], mul);
    tiger_round(a, b, c, x[6], mul);
    tiger_round(b, c, a, x[7], mul);
}

/* ---- Tiger compress: process one 64-byte block ---------------------- */
static void tiger_compress(const uint8_t *block, uint64_t state[3]) {
    uint64_t a = state[0], b = state[1], c = state[2];
    uint64_t x[8], tmp;

    /* Load block as little-endian uint64 words */
    memcpy(x, block, 64);
    /* On big-endian systems you'd need le64toh here.
       This project targets little-endian (x86_64, wasm). */

    /* Pass 1 (mul=5) */
    tiger_pass(&a, &b, &c, x, 5);
    tmp = a; a = c; c = b; b = tmp;

    tiger_key_schedule(x);

    /* Pass 2 (mul=7) */
    tiger_pass(&a, &b, &c, x, 7);
    tmp = a; a = c; c = b; b = tmp;

    tiger_key_schedule(x);

    /* Pass 3 (mul=9) */
    tiger_pass(&a, &b, &c, x, 9);

    /* Feed-forward */
    state[0] = a ^ state[0];
    state[1] = b - state[1];
    state[2] = c + state[2];
}

/* ---- Public API ----------------------------------------------------- */

void tiger_init(TIGER_CTX *ctx) {
    ctx->state[0] = 0x0123456789ABCDEFULL;
    ctx->state[1] = 0xFEDCBA9876543210ULL;
    ctx->state[2] = 0xF096A5B4C3B2E187ULL;
    ctx->count = 0;
    memset(ctx->buffer, 0, TIGER_BLOCK_SIZE);
}

void tiger_update(TIGER_CTX *ctx, const uint8_t *data, size_t len) {
    size_t idx = (size_t)(ctx->count & 0x3F);
    ctx->count += len;

    /* Fill partial buffer */
    if (idx) {
        size_t fill = TIGER_BLOCK_SIZE - idx;
        if (len < fill) {
            memcpy(ctx->buffer + idx, data, len);
            return;
        }
        memcpy(ctx->buffer + idx, data, fill);
        tiger_compress(ctx->buffer, ctx->state);
        data += fill;
        len  -= fill;
    }

    /* Process full blocks */
    while (len >= TIGER_BLOCK_SIZE) {
        uint8_t aligned[TIGER_BLOCK_SIZE];
        memcpy(aligned, data, TIGER_BLOCK_SIZE);
        tiger_compress(aligned, ctx->state);
        data += TIGER_BLOCK_SIZE;
        len  -= TIGER_BLOCK_SIZE;
    }

    /* Buffer remainder */
    if (len)
        memcpy(ctx->buffer, data, len);
}

void tiger_final(uint8_t digest[TIGER_DIGEST_LENGTH], TIGER_CTX *ctx) {
    uint64_t bits = ctx->count * 8;
    size_t idx = (size_t)(ctx->count & 0x3F);

    /* Pad: Tiger uses 0x01 (not 0x80 like MD/SHA), then zeros */
    ctx->buffer[idx++] = 0x01;

    if (idx > 56) {
        memset(ctx->buffer + idx, 0, TIGER_BLOCK_SIZE - idx);
        tiger_compress(ctx->buffer, ctx->state);
        idx = 0;
    }
    memset(ctx->buffer + idx, 0, 56 - idx);

    /* Append bit count as little-endian uint64 */
    memcpy(ctx->buffer + 56, &bits, 8);

    tiger_compress(ctx->buffer, ctx->state);

    /* Output state as little-endian bytes */
    memcpy(digest,      &ctx->state[0], 8);
    memcpy(digest + 8,  &ctx->state[1], 8);
    memcpy(digest + 16, &ctx->state[2], 8);

    /* Wipe */
    memset(ctx, 0, sizeof(*ctx));
}

void tiger_hash(const uint8_t *data, size_t len, uint8_t digest[TIGER_DIGEST_LENGTH]) {
    TIGER_CTX ctx;
    tiger_init(&ctx);
    tiger_update(&ctx, data, len);
    tiger_final(digest, &ctx);
}
