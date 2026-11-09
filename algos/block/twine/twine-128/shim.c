/* NextSSL adapter (not upstream code): owns one key schedule of the ported cipher and only calls the port's functions. */
#include <stdlib.h>
#include <string.h>
#include "twine.h"

static void wipe(void *p, size_t n) {
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}

void *shim_new(const unsigned char *key, int keylen) {
    twine_ctx *c;
    if (keylen != 16) return NULL;
    c = (twine_ctx *)calloc(1, sizeof(twine_ctx));
    if (c == NULL) return NULL;
    if ((twine_key_schedule_128(c, key), 0)) {
        wipe(c, sizeof(twine_ctx));
        free(c);
        return NULL;
    }
    return c;
}

int shim_enc(const void *c, const unsigned char *in, unsigned char *out) {
    twine_encrypt((const twine_ctx *)c, in, out);
    return 0;
}

int shim_dec(const void *c, const unsigned char *in, unsigned char *out) {
    twine_decrypt((const twine_ctx *)c, in, out);
    return 0;
}

void shim_free(void *c) {
    if (c != NULL) {
        wipe(c, sizeof(twine_ctx));
        free(c);
    }
}
