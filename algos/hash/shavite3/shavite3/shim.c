#include <stddef.h>
#include "sph_shavite.h"

/* NextSSL adapter (not upstream code): one-shot digest of `len` bytes into `out`; the output
 * length selects the variant. The sphlib context is wiped before return. */
static void wipe(void *p, size_t n) {
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}

int nextssl__shavite3__digest(unsigned out_len, const void *data, size_t len, void *out) {
    switch (out_len) {
    case 28: {
        sph_shavite224_context c;
        sph_shavite224_init(&c);
        sph_shavite224(&c, data, len);
        sph_shavite224_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 32: {
        sph_shavite256_context c;
        sph_shavite256_init(&c);
        sph_shavite256(&c, data, len);
        sph_shavite256_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 48: {
        sph_shavite384_context c;
        sph_shavite384_init(&c);
        sph_shavite384(&c, data, len);
        sph_shavite384_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 64: {
        sph_shavite512_context c;
        sph_shavite512_init(&c);
        sph_shavite512(&c, data, len);
        sph_shavite512_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    default:
        return -1;
    }
}
