/* Generated shim (not crypto): calls upstream spooky_hash128 with seeds 0 and returns 16 bytes, high-to-low big-endian. */
#include <stddef.h>
#include <stdint.h>
#include "spooky.h"

void shim_hash(const unsigned char *data, size_t len, unsigned char *out) {
    uint64_t h1 = 0, h2 = 0;
    int i;
    spooky_hash128(data, len, &h1, &h2);
    for (i = 0; i < 8; i++) {
        out[i] = (unsigned char)(h1 >> (56 - 8 * i));
        out[8 + i] = (unsigned char)(h2 >> (56 - 8 * i));
    }
}
