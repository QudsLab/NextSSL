/* Generated shim (not crypto): one-shot SHA-1 with collision detection; only calls upstream SHA1DC*. Returns -1 if upstream reports a collision attack. */
#include <stddef.h>
#include "sha1.h"

int shim_hash(unsigned char *out, const unsigned char *in, unsigned long long len) {
    SHA1_CTX c;
    SHA1DCInit(&c);
    while (len > 0) {
        size_t n = len > 0x40000000ULL ? (size_t)0x40000000 : (size_t)len;
        SHA1DCUpdate(&c, (const char *)in, n);
        in += n;
        len -= n;
    }
    return SHA1DCFinal(out, &c) ? -1 : 0;
}
