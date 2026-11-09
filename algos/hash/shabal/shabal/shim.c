#include <stddef.h>
#include "sph_shabal.h"

/* NextSSL adapter (not upstream code): one-shot digest of `len` bytes into `out`; the output
 * length selects the variant. The sphlib context is wiped before return. */
static void wipe(void *p, size_t n) {
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}

int nextssl__shabal__digest(unsigned out_len, const void *data, size_t len, void *out) {
    switch (out_len) {
    case 28: {
        sph_shabal224_context c;
        sph_shabal224_init(&c);
        sph_shabal224(&c, data, len);
        sph_shabal224_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 32: {
        sph_shabal256_context c;
        sph_shabal256_init(&c);
        sph_shabal256(&c, data, len);
        sph_shabal256_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 48: {
        sph_shabal384_context c;
        sph_shabal384_init(&c);
        sph_shabal384(&c, data, len);
        sph_shabal384_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 64: {
        sph_shabal512_context c;
        sph_shabal512_init(&c);
        sph_shabal512(&c, data, len);
        sph_shabal512_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    default:
        return -1;
    }
}
