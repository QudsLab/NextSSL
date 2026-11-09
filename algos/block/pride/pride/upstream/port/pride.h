/* C translation of pypride.py (https://github.com/obfusk/pypride, commit 97d724c086a0f498bdd049ddaf0b6f9e30822492,
 * Copyright (C) 2016 Felix C. Stegerman, LGPL-3.0-or-later). Line-by-line port, see ../ORIGIN.md. */
#ifndef PRIDE_H
#define PRIDE_H
#include <stdint.h>

#define PRIDE_MAX_ROUNDS 64

typedef struct {
    uint64_t k0;
    uint64_t roundkeys[PRIDE_MAX_ROUNDS];
    int rounds;
} pride_ctx;

/* Pride.__init__: key is 16 bytes, 1 <= rounds <= PRIDE_MAX_ROUNDS (the original default is 20). Returns 0, or -1. */
int pride_init(pride_ctx *c, const uint8_t key[16], int rounds);
/* Pride.encrypt / Pride.decrypt on one 8-byte block (big-endian integer, as b2i/i2b). */
void pride_encrypt(const pride_ctx *c, const uint8_t in[8], uint8_t out[8]);
void pride_decrypt(const pride_ctx *c, const uint8_t in[8], uint8_t out[8]);
#endif
