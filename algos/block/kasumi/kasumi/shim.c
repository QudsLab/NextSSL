/* Generated shim (not crypto): owns one upstream key schedule and only calls the upstream functions. */
#include <stdlib.h>
#include "tomcrypt.h"

void *shim_new(const unsigned char *key, int keylen) {
    symmetric_key *s = (symmetric_key *)calloc(1, sizeof(symmetric_key));
    if (s == NULL) return NULL;
    if (kasumi_setup(key, keylen, 0, s) != CRYPT_OK) {
        zeromem(s, sizeof(symmetric_key));
        free(s);
        return NULL;
    }
    return s;
}

int shim_enc(const void *c, const unsigned char *in, unsigned char *out) {
    return kasumi_ecb_encrypt(in, out, (const symmetric_key *)c) == CRYPT_OK ? 0 : -1;
}

int shim_dec(const void *c, const unsigned char *in, unsigned char *out) {
    return kasumi_ecb_decrypt(in, out, (const symmetric_key *)c) == CRYPT_OK ? 0 : -1;
}

void shim_free(void *c) {
    if (c != NULL) {
        zeromem(c, sizeof(symmetric_key));
        free(c);
    }
}
