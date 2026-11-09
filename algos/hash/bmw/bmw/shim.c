#include <stddef.h>
#include "sph_bmw.h"

/* NextSSL adapter (not upstream code): one-shot digest of `len` bytes into `out`; the output
 * length selects the variant. The sphlib context is wiped before return. */
static void wipe(void *p, size_t n) {
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}

int nextssl__bmw__digest(unsigned out_len, const void *data, size_t len, void *out) {
    switch (out_len) {
    case 28: {
        sph_bmw224_context c;
        sph_bmw224_init(&c);
        sph_bmw224(&c, data, len);
        sph_bmw224_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 32: {
        sph_bmw256_context c;
        sph_bmw256_init(&c);
        sph_bmw256(&c, data, len);
        sph_bmw256_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 48: {
        sph_bmw384_context c;
        sph_bmw384_init(&c);
        sph_bmw384(&c, data, len);
        sph_bmw384_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 64: {
        sph_bmw512_context c;
        sph_bmw512_init(&c);
        sph_bmw512(&c, data, len);
        sph_bmw512_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    default:
        return -1;
    }
}
