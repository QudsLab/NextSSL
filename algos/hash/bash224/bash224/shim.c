/* Shim (not crypto): one-shot wrapper over libecc bash224(); it only calls the upstream function. */
#include "hash/bash224.h"

int shim_hash(unsigned char *out, const unsigned char *in, unsigned long len) {
    if (len > 0xFFFFFFFFul) return -1;
    return bash224(in, (u32)len, out) == 0 ? 0 : -1;
}
