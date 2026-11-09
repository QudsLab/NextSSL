#include <stddef.h>
#include "sph_sha0.h"

/* NextSSL adapter (not upstream code): one-shot digest. The upstream context is wiped before return. */
static void wipe(void *p, size_t n) {
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}

int nextssl__sha0__digest(const void *data, size_t len, void *out) {
    sph_sha0_context c;
    sph_sha0_init(&c);
    sph_sha0(&c, data, len);
    sph_sha0_close(&c, out);
    wipe(&c, sizeof c);
    return 0;
}
