#include <stddef.h>
#include "sph_luffa.h"

/* NextSSL adapter (not upstream code): one-shot digest of `len` bytes into `out`; the output
 * length selects the variant. The sphlib context is wiped before return. */
static void wipe(void *p, size_t n) {
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}

int nextssl__luffa__digest(unsigned out_len, const void *data, size_t len, void *out) {
    switch (out_len) {
    case 28: {
        sph_luffa224_context c;
        sph_luffa224_init(&c);
        sph_luffa224(&c, data, len);
        sph_luffa224_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 32: {
        sph_luffa256_context c;
        sph_luffa256_init(&c);
        sph_luffa256(&c, data, len);
        sph_luffa256_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 48: {
        sph_luffa384_context c;
        sph_luffa384_init(&c);
        sph_luffa384(&c, data, len);
        sph_luffa384_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 64: {
        sph_luffa512_context c;
        sph_luffa512_init(&c);
        sph_luffa512(&c, data, len);
        sph_luffa512_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    default:
        return -1;
    }
}
