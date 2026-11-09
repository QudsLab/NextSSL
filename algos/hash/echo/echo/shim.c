#include <stddef.h>
#include "sph_echo.h"

/* NextSSL adapter (not upstream code): one-shot digest of `len` bytes into `out`; the output
 * length selects the variant. The sphlib context is wiped before return. */
static void wipe(void *p, size_t n) {
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}

int nextssl__echo__digest(unsigned out_len, const void *data, size_t len, void *out) {
    switch (out_len) {
    case 28: {
        sph_echo224_context c;
        sph_echo224_init(&c);
        sph_echo224(&c, data, len);
        sph_echo224_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 32: {
        sph_echo256_context c;
        sph_echo256_init(&c);
        sph_echo256(&c, data, len);
        sph_echo256_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 48: {
        sph_echo384_context c;
        sph_echo384_init(&c);
        sph_echo384(&c, data, len);
        sph_echo384_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    case 64: {
        sph_echo512_context c;
        sph_echo512_init(&c);
        sph_echo512(&c, data, len);
        sph_echo512_close(&c, out);
        wipe(&c, sizeof c);
        return 0;
    }
    default:
        return -1;
    }
}
