/* Generated shim (not crypto): owns one upstream ICE key and only calls the upstream ice_key_* functions. */
#include <stdlib.h>
#include "ice.h"

void *shim_new(const unsigned char *key, int keylen) {
    ICE_KEY *k;
    if (keylen != 16) return NULL;
    k = ice_key_create(2);
    if (k == NULL) return NULL;
    if (ice_key_key_size(k) != keylen) {
        ice_key_destroy(k);
        return NULL;
    }
    ice_key_set(k, key);
    return k;
}

int shim_enc(const void *p, const unsigned char *in, unsigned char *out) {
    ice_key_encrypt((const ICE_KEY *)p, in, out);
    return 0;
}

int shim_dec(const void *p, const unsigned char *in, unsigned char *out) {
    ice_key_decrypt((const ICE_KEY *)p, in, out);
    return 0;
}

void shim_free(void *p) {
    if (p != NULL) ice_key_destroy((ICE_KEY *)p);
}
