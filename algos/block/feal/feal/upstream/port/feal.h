/* C translation of FEAL/feal_nx.py and the helper functions F2, Fk, S0, S1 of FEAL/utils.py from
 * https://github.com/Vozec/Feal-ALL (commit 9d01773dd69205eb24c3f541455356e6802c39f0, no license stated).
 * Line-by-line port, see ../ORIGIN.md. FEAL-NX: 64-bit block, 128-bit key, N rounds (even). */
#ifndef FEAL_H
#define FEAL_H
#include <stdint.h>

#define FEAL_MAX_ROUNDS 64

typedef struct {
    int n;
    uint8_t subkey[2 * FEAL_MAX_ROUNDS + 16]; /* 4 * (n/2 + 4) bytes used */
} feal_nx_ctx;

/* Feal_NX.__init__ + key_generation. key is 16 bytes; n even, 2 <= n <= FEAL_MAX_ROUNDS. Returns 0, or -1.
 * The original has no check for odd n; its encrypt/decrypt then fail on an xor length assertion. */
int feal_nx_init(feal_nx_ctx *c, const uint8_t key[16], int n);
/* Feal_NX.encrypt / decrypt on one 8-byte block. */
void feal_nx_encrypt(const feal_nx_ctx *c, const uint8_t in[8], uint8_t out[8]);
void feal_nx_decrypt(const feal_nx_ctx *c, const uint8_t in[8], uint8_t out[8]);
#endif
