#include <stddef.h>
#include "sph_simd.h"

/* NextSSL adapter (not upstream code): one-shot digest of `len` bytes into `out`; the output
 * length selects the variant. The sphlib context is wiped before return. */
static void wipe(void *p, size_t n) {
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}

int nextssl__simd__digest(unsigned out_len, const void *data, size_t len, void *out) {
    switch (out_len) {
    case 28: {
        sph_simd224_context c;
        sph_simd224_init(&c);
        sph_simd224(&c, data, len);
        sph_simd224_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 32: {
        sph_simd256_context c;
        sph_simd256_init(&c);
        sph_simd256(&c, data, len);
        sph_simd256_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 48: {
        sph_simd384_context c;
        sph_simd384_init(&c);
        sph_simd384(&c, data, len);
        sph_simd384_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 64: {
        sph_simd512_context c;
        sph_simd512_init(&c);
        sph_simd512(&c, data, len);
        sph_simd512_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    default:
        return -1;
    }
}
