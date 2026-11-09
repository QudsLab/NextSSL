/* C translation of pypride.py (https://github.com/obfusk/pypride, commit 97d724c086a0f498bdd049ddaf0b6f9e30822492,
 * Copyright (C) 2016 Felix C. Stegerman, LGPL-3.0-or-later). Line-by-line port, see ../ORIGIN.md. */
#include <stddef.h>
#include "pride.h"

static const int S[16] = { 0x0, 0x4, 0x8, 0xF, 0x1, 0x5, 0xE, 0x9,
                           0x2, 0x7, 0xA, 0xC, 0xB, 0xD, 0x6, 0x3 };

/* L0..L3 and inverses, rows copied from the original binary literals (L0_inv = L0, L3_inv = L3). */
static const uint16_t L0[16] = {0x0888, 0x0444, 0x0222, 0x0111, 0x8088, 0x4044, 0x2022, 0x1011, 0x8808, 0x4404, 0x2202, 0x1101, 0x8880, 0x4440, 0x2220, 0x1110};
static const uint16_t L1[16] = {0xc010, 0x6008, 0x3004, 0x1802, 0x0c01, 0x0680, 0x0340, 0x8120, 0x8018, 0x400c, 0x2006, 0x1003, 0x0881, 0x04c0, 0x0260, 0x0130};
static const uint16_t L2[16] = {0x0c01, 0x0680, 0x0340, 0x8120, 0xc010, 0x6008, 0x3004, 0x1802, 0x0881, 0x04c0, 0x0260, 0x0130, 0x8018, 0x400c, 0x2006, 0x1003};
static const uint16_t L3[16] = {0x8808, 0x4404, 0x2202, 0x1101, 0x8880, 0x4440, 0x2220, 0x1110, 0x0888, 0x0444, 0x0222, 0x0111, 0x8088, 0x4044, 0x2022, 0x1011};
static const uint16_t L1_inv[16] = {0x0302, 0x8101, 0xc080, 0x6040, 0x3020, 0x1810, 0x0c08, 0x0604, 0x1018, 0x080c, 0x0406, 0x0203, 0x0181, 0x80c0, 0x4060, 0x2030};
static const uint16_t L2_inv[16] = {0x3020, 0x1810, 0x0c08, 0x0604, 0x0302, 0x8101, 0xc080, 0x6040, 0x0181, 0x80c0, 0x4060, 0x2030, 0x1018, 0x080c, 0x0406, 0x0203};

/* p(): permutation matrix. P_inv[i] = P.index(i); S_inv[i] = S.index(i). Built per call, no shared state. */
static void tables(int P[64], int P_inv[64], int S_inv[16]) {
    int i, j;
    for (i = 0; i < 64; i++) P[i] = -1;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 16; j++)
            P[63 - (j * 4 + i)] = (3 - i) * 16 + (15 - j);
    for (i = 0; i < 64; i++)
        for (j = 0; j < 64; j++)
            if (P[j] == i) { P_inv[i] = j; break; }
    for (i = 0; i < 16; i++)
        for (j = 0; j < 16; j++)
            if (S[j] == i) { S_inv[i] = j; break; }
}

static uint64_t p_layer(uint64_t state, const int *p) {
    uint64_t state_ = 0;
    int i;
    for (i = 0; i < 64; i++)
        state_ |= ((state >> i) & 1) << p[i];
    return state_;
}

static uint64_t s_layer(uint64_t state, const int *s) {
    uint64_t state_ = 0;
    int i;
    for (i = 0; i < 16; i++)
        state_ |= (uint64_t)s[(state >> (i * 4)) & 0xF] << (i * 4);
    return state_;
}

/* matrix_mult: bin(r & v).count('1') % 2 */
static uint16_t matrix_mult(const uint16_t m[16], uint16_t v) {
    uint16_t w = 0;
    int i;
    for (i = 0; i < 16; i++) {
        unsigned r = (unsigned)(m[i] & v), cnt = 0;
        while (r) { cnt += r & 1; r >>= 1; }
        w |= (uint16_t)((cnt % 2) << (15 - i));
    }
    return w;
}

static uint64_t l_layer(uint64_t state, int inv) {
    const uint16_t *l[4];
    uint64_t state_ = 0;
    int i;
    if (!inv) { l[0] = L3; l[1] = L2; l[2] = L1; l[3] = L0; }
    else      { l[0] = L3; l[1] = L2_inv; l[2] = L1_inv; l[3] = L0; }
    for (i = 0; i < 4; i++)
        state_ |= (uint64_t)matrix_mult(l[i], (uint16_t)((state >> (i * 16)) & 0xFFFF)) << (i * 16);
    return state_;
}

static uint64_t b2i8(const uint8_t *x) {
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) v = (v << 8) | x[i];
    return v;
}

static void i2b8(uint64_t v, uint8_t *o) {
    int i;
    for (i = 7; i >= 0; i--) { o[i] = (uint8_t)(v & 0xFF); v >>= 8; }
}

/* g(x, i, j): (x + m[j]*i) % 256 */
static uint8_t g(uint8_t x, int i, int j) {
    static const int m[4] = { 193, 165, 81, 197 };
    return (uint8_t)((x + m[j] * i) % 256);
}

/* f(i, k1): round key as integer */
static uint64_t f(int i, const uint8_t *k1) {
    uint8_t b[8];
    int j;
    for (j = 0; j < 8; j++)
        b[j] = (j % 2) ? g(k1[j], i, j / 2) : k1[j];
    return b2i8(b);
}

int pride_init(pride_ctx *c, const uint8_t key[16], int rounds) {
    int i;
    if (rounds < 1 || rounds > PRIDE_MAX_ROUNDS) return -1;
    c->k0 = b2i8(key);
    c->rounds = rounds;
    for (i = 0; i < rounds; i++)
        c->roundkeys[i] = f(i + 1, key + 8);
    return 0;
}

void pride_encrypt(const pride_ctx *c, const uint8_t in[8], uint8_t out[8]) {
    int P[64], P_inv[64], S_inv[16], i;
    uint64_t state;
    tables(P, P_inv, S_inv);
    state = b2i8(in);
    state = p_layer(state, P_inv);
    state ^= c->k0;
    for (i = 0; i < c->rounds; i++) {
        state ^= p_layer(c->roundkeys[i], P_inv);
        state = s_layer(state, S);
        if (i != c->rounds - 1) {
            state = p_layer(state, P);
            state = l_layer(state, 0);
            state = p_layer(state, P_inv);
        }
    }
    state ^= c->k0; /* k2 = k0 */
    state = p_layer(state, P);
    i2b8(state, out);
}

void pride_decrypt(const pride_ctx *c, const uint8_t in[8], uint8_t out[8]) {
    int P[64], P_inv[64], S_inv[16], i;
    uint64_t state;
    tables(P, P_inv, S_inv);
    state = b2i8(in);
    state = p_layer(state, P_inv);
    state ^= c->k0; /* k2 = k0 */
    for (i = 0; i < c->rounds; i++) {
        state = s_layer(state, S_inv);
        state ^= p_layer(c->roundkeys[c->rounds - 1 - i], P_inv);
        if (i != c->rounds - 1) {
            state = p_layer(state, P);
            state = l_layer(state, 1);
            state = p_layer(state, P_inv);
        }
    }
    state ^= c->k0;
    state = p_layer(state, P);
    i2b8(state, out);
}
