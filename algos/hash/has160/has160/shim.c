#include <stddef.h>
#include "has160.h"

/* NextSSL adapter (not upstream code): one-shot digest. The upstream context is wiped before return. */
static void wipe(void *p, size_t n) {
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}

int nextssl__has160__digest(const void *data, size_t len, void *out) {
    has160_ctx c;
    rhash_has160_init(&c);
    rhash_has160_update(&c, (const unsigned char *)data, len);
    rhash_has160_final(&c, (unsigned char *)out);
    wipe(&c, sizeof c);
    return 0;
}
