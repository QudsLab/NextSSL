/* C translation of FEAL/feal_nx.py and FEAL/utils.py from https://github.com/Vozec/Feal-ALL
 * (commit 9d01773dd69205eb24c3f541455356e6802c39f0, no license stated). Line-by-line port, see ../ORIGIN.md. */
#include <stddef.h>
#include <string.h>
#include "feal.h"

/* S0(X1, X2, k): rot2((X1 + X2 + k) % 256) % 256 */
static uint8_t S0(unsigned x1, unsigned x2, unsigned k) {
    unsigned t = (x1 + x2 + k) % 256;
    return (uint8_t)(((t << 2) | (t >> 6)) % 256);
}
static uint8_t S1(unsigned x1, unsigned x2) { return S0(x1, x2, 1); }

/* F2(a, b): a is 4 bytes, b is 2 bytes */
static void F2(const uint8_t a[4], const uint8_t b[2], uint8_t f[4]) {
    uint8_t f0, f1, f2, f3;
    f1 = a[1] ^ b[0];
    f2 = a[2] ^ b[1];
    f1 = f1 ^ a[0];
    f2 = f2 ^ a[3];
    f1 = S1(f1, f2);
    f2 = S0(f2, f1, 0);
    f0 = S0(a[0], f1, 0);
    f3 = S1(a[3], f2);
    f[0] = f0; f[1] = f1; f[2] = f2; f[3] = f3;
}

/* Fk(a, b): both 4 bytes */
static void Fk(const uint8_t a[4], const uint8_t b[4], uint8_t f[4]) {
    uint8_t fk0, fk1, fk2, fk3;
    fk1 = a[1] ^ a[0];
    fk2 = a[2] ^ a[3];
    fk1 = S1(fk1, fk2 ^ b[0]);
    fk2 = S0(fk2, fk1 ^ b[1], 0);
    fk0 = S0(a[0], fk1 ^ b[2], 0);
    fk3 = S1(a[3], fk2 ^ b[3]);
    f[0] = fk0; f[1] = fk1; f[2] = fk2; f[3] = fk3;
}

int feal_nx_init(feal_nx_ctx *c, const uint8_t key[16], int n) {
    uint8_t Kr1[4], Kr2[4], Qr[4], A0[4], B0[4], D0[4], xored[4], t[4];
    int i, k;
    if (n < 2 || n > FEAL_MAX_ROUNDS || (n & 1)) return -1;
    c->n = n;
    memcpy(Kr1, key + 8, 4);
    memcpy(Kr2, key + 12, 4);
    for (k = 0; k < 4; k++) Qr[k] = Kr1[k] ^ Kr2[k];
    memcpy(A0, key, 4);
    memcpy(B0, key + 4, 4);
    memset(D0, 0, 4);
    for (i = 0; i < n / 2 + 4; i++) {
        if (i % 3 == 1) for (k = 0; k < 4; k++) xored[k] = B0[k] ^ Kr1[k];
        else if (i % 3 == 0) for (k = 0; k < 4; k++) xored[k] = B0[k] ^ Qr[k];
        else for (k = 0; k < 4; k++) xored[k] = B0[k] ^ Kr2[k];
        if (i > 0) for (k = 0; k < 4; k++) xored[k] ^= D0[k];
        memcpy(D0, A0, 4);
        Fk(A0, xored, t);
        memcpy(A0, t, 4);
        memcpy(c->subkey + 4 * i, A0, 4);
        /* A0, B0 = B0, A0 */
        memcpy(t, A0, 4);
        memcpy(A0, B0, 4);
        memcpy(B0, t, 4);
    }
    return 0;
}

void feal_nx_encrypt(const feal_nx_ctx *c, const uint8_t in[8], uint8_t out[8]) {
    uint8_t L[4], R[4], f[4], t[4];
    int i, k, N = c->n;
    memcpy(L, in, 4);
    memcpy(R, in + 4, 4);
    for (k = 0; k < 4; k++) { L[k] ^= c->subkey[2 * N + k]; R[k] ^= c->subkey[2 * N + 4 + k]; }
    for (k = 0; k < 4; k++) R[k] ^= L[k];
    for (i = 0; i < N; i++) {
        F2(R, c->subkey + 2 * i, f);
        for (k = 0; k < 4; k++) L[k] ^= f[k];
        memcpy(t, L, 4); memcpy(L, R, 4); memcpy(R, t, 4);
    }
    /* (R, L) = (R, L) xor (0, R) */
    for (k = 0; k < 4; k++) L[k] ^= R[k];
    for (k = 0; k < 4; k++) { R[k] ^= c->subkey[2 * N + 8 + k]; L[k] ^= c->subkey[2 * N + 12 + k]; }
    memcpy(out, R, 4);
    memcpy(out + 4, L, 4);
}

void feal_nx_decrypt(const feal_nx_ctx *c, const uint8_t in[8], uint8_t out[8]) {
    uint8_t L[4], R[4], f[4], t[4];
    int i, k, N = c->n;
    memcpy(R, in, 4);
    memcpy(L, in + 4, 4);
    for (k = 0; k < 4; k++) { R[k] ^= c->subkey[2 * N + 8 + k]; L[k] ^= c->subkey[2 * N + 12 + k]; }
    for (k = 0; k < 4; k++) L[k] ^= R[k];
    for (i = N - 1; i >= 0; i--) {
        memcpy(t, L, 4); memcpy(L, R, 4); memcpy(R, t, 4);
        F2(R, c->subkey + 2 * i, f);
        for (k = 0; k < 4; k++) L[k] ^= f[k];
    }
    /* (L, R) = (L, R) xor (0, L) */
    for (k = 0; k < 4; k++) R[k] ^= L[k];
    for (k = 0; k < 4; k++) { L[k] ^= c->subkey[2 * N + k]; R[k] ^= c->subkey[2 * N + 4 + k]; }
    memcpy(out, L, 4);
    memcpy(out + 4, R, 4);
}
