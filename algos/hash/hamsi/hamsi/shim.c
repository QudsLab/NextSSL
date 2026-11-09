#include <stddef.h>
#include "sph_hamsi.h"

/* NextSSL adapter (not upstream code): one-shot digest of `len` bytes into `out`; the output
 * length selects the variant. The sphlib context is wiped before return. */
static void wipe(void *p, size_t n) {
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}

int nextssl__hamsi__digest(unsigned out_len, const void *data, size_t len, void *out) {
    switch (out_len) {
    case 28: {
        sph_hamsi224_context c;
        sph_hamsi224_init(&c);
        sph_hamsi224(&c, data, len);
        sph_hamsi224_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 32: {
        sph_hamsi256_context c;
        sph_hamsi256_init(&c);
        sph_hamsi256(&c, data, len);
        sph_hamsi256_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 48: {
        sph_hamsi384_context c;
        sph_hamsi384_init(&c);
        sph_hamsi384(&c, data, len);
        sph_hamsi384_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 64: {
        sph_hamsi512_context c;
        sph_hamsi512_init(&c);
        sph_hamsi512(&c, data, len);
        sph_hamsi512_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    default:
        return -1;
    }
}
