/* sha3_512.c — SHA3-512 (rate=72, capacity=128, output=64 bytes) */
#include "sha3_512.h"
#include "keccak.h"
#include <string.h>

void sha3_512_hash(const uint8_t *in, size_t inlen, uint8_t out[64]) {
    keccak_hash(in, inlen, out, 64, 72, 0x06);
}
