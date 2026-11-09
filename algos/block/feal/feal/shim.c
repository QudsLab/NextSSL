/* NextSSL adapter (not upstream code): owns one key schedule of the ported cipher and only calls the port's functions. */
#include <stdlib.h>
#include <string.h>
#include "feal.h"

static void wipe(void *p, size_t n) {
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}

void *shim_new(const unsigned char *key, int keylen) {
    feal_nx_ctx *c;
    if (keylen != 16) return NULL;
    c = (feal_nx_ctx *)calloc(1, sizeof(feal_nx_ctx));
    if (c == NULL) return NULL;
    if (feal_nx_init(c, key, 32) != 0) {
        wipe(c, sizeof(feal_nx_ctx));
        free(c);
        return NULL;
    }
    return c;
}

int shim_enc(const void *c, const unsigned char *in, unsigned char *out) {
    feal_nx_encrypt((const feal_nx_ctx *)c, in, out);
    return 0;
}

int shim_dec(const void *c, const unsigned char *in, unsigned char *out) {
    feal_nx_decrypt((const feal_nx_ctx *)c, in, out);
    return 0;
}

void shim_free(void *c) {
    if (c != NULL) {
        wipe(c, sizeof(feal_nx_ctx));
        free(c);
    }
}
