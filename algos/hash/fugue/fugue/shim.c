#include <stddef.h>
#include "sph_fugue.h"

/* NextSSL adapter (not upstream code): one-shot digest of `len` bytes into `out`; the output
 * length selects the variant. The sphlib context is wiped before return. */
static void wipe(void *p, size_t n) {
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}

int nextssl__fugue__digest(unsigned out_len, const void *data, size_t len, void *out) {
    switch (out_len) {
    case 28: {
        sph_fugue224_context c;
        sph_fugue224_init(&c);
        sph_fugue224(&c, data, len);
        sph_fugue224_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 32: {
        sph_fugue256_context c;
        sph_fugue256_init(&c);
        sph_fugue256(&c, data, len);
        sph_fugue256_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 48: {
        sph_fugue384_context c;
        sph_fugue384_init(&c);
        sph_fugue384(&c, data, len);
        sph_fugue384_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 64: {
        sph_fugue512_context c;
        sph_fugue512_init(&c);
        sph_fugue512(&c, data, len);
        sph_fugue512_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    default:
        return -1;
    }
}
