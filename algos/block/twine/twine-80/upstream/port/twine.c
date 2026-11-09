/* C translation of src/algo.py of https://github.com/amoallim15/xtwine (commit fa1e0706ef92afc2ef3031c16e16c3b6232cb5b3,
 * MIT). Line-by-line port, see ../ORIGIN.md. */
#include <stddef.h>
#include "twine.h"

static const uint8_t sbox[16] = { 0xC, 0x0, 0xF, 0xA, 0x2, 0xB, 0x9, 0x5, 0x8, 0x3, 0xD, 0x7, 0x1, 0xE, 0x6, 0x4 };
static const uint8_t permutation_enc[16] = { 0x5, 0x0, 0x1, 0x4, 0x7, 0xC, 0x3, 0x8, 0xD, 0x6, 0x9, 0x2, 0xF, 0xA, 0xB, 0xE };
static const uint8_t permutation_dec[16] = { 0x1, 0x2, 0xB, 0x6, 0x3, 0x0, 0x9, 0x4, 0x7, 0xA, 0xD, 0xE, 0x5, 0x8, 0xF, 0xC };
/* con[0x01..0x23]; index 0 unused */
static const uint8_t con[36] = {
    0x00,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x03, 0x06, 0x0C, 0x18, 0x30, 0x23, 0x05, 0x0A, 0x14, 0x28, 0x13, 0x26,
    0x0F, 0x1E, 0x3C, 0x3B, 0x35, 0x29, 0x11, 0x22, 0x07, 0x0E, 0x1C, 0x38, 0x33, 0x25, 0x09, 0x12, 0x24
};

#define S_(i) (sbox[(i)])
#define CON_L(r) (con[(r)] & 7)
#define CON_H(r) ((con[(r)] >> 3) & 7)

/* _Rot4(bits): bits[1:] + bits[:1] */
static void rot4(uint8_t *w) {
    uint8_t t = w[0];
    w[0] = w[1]; w[1] = w[2]; w[2] = w[3]; w[3] = t;
}

/* _Rot16(bits): bits[4:] + bits[:4] over n nibbles */
static void rot16(uint8_t *w, int n) {
    uint8_t t[4];
    int k;
    for (k = 0; k < 4; k++) t[k] = w[k];
    for (k = 0; k < n - 4; k++) w[k] = w[k + 4];
    for (k = 0; k < 4; k++) w[n - 4 + k] = t[k];
}

static void get_nibbles(const uint8_t *key, int n_bytes, uint8_t *wk) {
    int i;
    for (i = 0; i < n_bytes * 2; i++)
        wk[i] = (i % 2 == 0) ? (key[i / 2] >> 4) : (key[i / 2] & 0xF);
}

void twine_key_schedule_80(twine_ctx *c, const uint8_t key[10]) {
    uint8_t WK[20];
    int r;
    get_nibbles(key, 10, WK);
    for (r = 1; r < 36; r++) {
        c->rk[r][0] = WK[1]; c->rk[r][1] = WK[3]; c->rk[r][2] = WK[4]; c->rk[r][3] = WK[6];
        c->rk[r][4] = WK[13]; c->rk[r][5] = WK[14]; c->rk[r][6] = WK[15]; c->rk[r][7] = WK[16];
        WK[1] = WK[1] ^ S_(WK[0]);
        WK[4] = WK[4] ^ S_(WK[16]);
        WK[7] = WK[7] ^ CON_H(r);
        WK[19] = WK[19] ^ CON_L(r);
        rot4(WK);
        rot16(WK, 20);
    }
    c->rk[36][0] = WK[1]; c->rk[36][1] = WK[3]; c->rk[36][2] = WK[4]; c->rk[36][3] = WK[6];
    c->rk[36][4] = WK[13]; c->rk[36][5] = WK[14]; c->rk[36][6] = WK[15]; c->rk[36][7] = WK[16];
}

void twine_key_schedule_128(twine_ctx *c, const uint8_t key[16]) {
    uint8_t WK[32];
    int r;
    get_nibbles(key, 16, WK);
    for (r = 1; r < 36; r++) {
        c->rk[r][0] = WK[2]; c->rk[r][1] = WK[3]; c->rk[r][2] = WK[12]; c->rk[r][3] = WK[15];
        c->rk[r][4] = WK[17]; c->rk[r][5] = WK[18]; c->rk[r][6] = WK[28]; c->rk[r][7] = WK[31];
        WK[1] = WK[1] ^ S_(WK[0]);
        WK[4] = WK[4] ^ S_(WK[16]);
        WK[23] = WK[23] ^ S_(WK[30]);
        WK[7] = WK[7] ^ CON_H(r);
        WK[19] = WK[19] ^ CON_L(r);
        rot4(WK);
        rot16(WK, 32);
    }
    c->rk[36][0] = WK[2]; c->rk[36][1] = WK[3]; c->rk[36][2] = WK[12]; c->rk[36][3] = WK[15];
    c->rk[36][4] = WK[17]; c->rk[36][5] = WK[18]; c->rk[36][6] = WK[28]; c->rk[36][7] = WK[31];
}

static void round_fn(uint8_t *x, const uint8_t *rk) {
    int j;
    for (j = 0; j < 8; j++)
        x[2 * j + 1] = (uint8_t)(S_(x[2 * j] ^ rk[j]) ^ x[2 * j + 1]);
}

static void shuffle(uint8_t *x, const uint8_t *perm) {
    uint8_t y[16];
    int h;
    for (h = 0; h < 16; h++) y[perm[h]] = x[h];
    for (h = 0; h < 16; h++) x[h] = y[h];
}

void twine_encrypt(const twine_ctx *c, const uint8_t in[8], uint8_t out[8]) {
    uint8_t X[16];
    int i;
    get_nibbles(in, 8, X);
    for (i = 1; i < 36; i++) {
        round_fn(X, c->rk[i]);
        shuffle(X, permutation_enc);
    }
    round_fn(X, c->rk[36]);
    for (i = 0; i < 8; i++) out[i] = (uint8_t)((X[2 * i] << 4) | X[2 * i + 1]);
}

void twine_decrypt(const twine_ctx *c, const uint8_t in[8], uint8_t out[8]) {
    uint8_t X[16];
    int i;
    get_nibbles(in, 8, X);
    for (i = 36; i > 1; i--) {
        round_fn(X, c->rk[i]);
        shuffle(X, permutation_dec);
    }
    round_fn(X, c->rk[1]);
    for (i = 0; i < 8; i++) out[i] = (uint8_t)((X[2 * i] << 4) | X[2 * i + 1]);
}
