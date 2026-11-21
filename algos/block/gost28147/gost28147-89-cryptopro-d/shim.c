/* Shim (not crypto): owns one gost89.c key schedule (substitution block fixed at build time through NS_SBOX) and only calls the
 * upstream functions. gost_key_nomask is used so no randomness is needed. */
#include <stdlib.h>
#include <string.h>
#include "gost89.h"

void *shim_new(const unsigned char *key, int keylen) {
    gost_ctx *c;
    if (keylen != 32) return NULL;
    c = (gost_ctx *)calloc(1, sizeof(gost_ctx));
    if (c == NULL) return NULL;
    gost_init(c, &NS_SBOX);
    gost_key_nomask(c, key);
    return c;
}

int shim_enc(const void *c, const unsigned char *in, unsigned char *out) {
    gostcrypt((gost_ctx *)c, in, out);
    return 0;
}

int shim_dec(const void *c, const unsigned char *in, unsigned char *out) {
    gostdecrypt((gost_ctx *)c, in, out);
    return 0;
}

void shim_free(void *c) {
    if (c != NULL) {
        gost_destroy((gost_ctx *)c);
        free(c);
    }
}
