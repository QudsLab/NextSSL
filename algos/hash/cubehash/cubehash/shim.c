#include <stddef.h>
#include "sph_cubehash.h"

/* NextSSL adapter (not upstream code): one-shot digest of `len` bytes into `out`; the output
 * length selects the variant. The sphlib context is wiped before return. */
static void wipe(void *p, size_t n) {
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}

int nextssl__cubehash__digest(unsigned out_len, const void *data, size_t len, void *out) {
    switch (out_len) {
    case 28: {
        sph_cubehash224_context c;
        sph_cubehash224_init(&c);
        sph_cubehash224(&c, data, len);
        sph_cubehash224_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 32: {
        sph_cubehash256_context c;
        sph_cubehash256_init(&c);
        sph_cubehash256(&c, data, len);
        sph_cubehash256_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 48: {
        sph_cubehash384_context c;
        sph_cubehash384_init(&c);
        sph_cubehash384(&c, data, len);
        sph_cubehash384_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 64: {
        sph_cubehash512_context c;
        sph_cubehash512_init(&c);
        sph_cubehash512(&c, data, len);
        sph_cubehash512_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    default:
        return -1;
    }
}
