/* Generated shim (not crypto): extern "C" entry points that only call the upstream C++ functions. */
#include <stddef.h>
#include "api.h"

int crypto_aead_encrypt(unsigned char *c,unsigned long long *clen, const unsigned char *m,unsigned long long mlen, const unsigned char *ad,unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k);
int crypto_aead_decrypt(unsigned char *m,unsigned long long *mlen, unsigned char *nsec, const unsigned char *c,unsigned long long clen, const unsigned char *ad,unsigned long long adlen, const unsigned char *npub, const unsigned char *k);

extern "C" int shim_aead_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m,
                                 unsigned long long mlen, const unsigned char *ad, unsigned long long adlen,
                                 const unsigned char *nsec, const unsigned char *npub, const unsigned char *k) {
    return crypto_aead_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k);
}

extern "C" int shim_aead_decrypt(unsigned char *m, unsigned long long *mlen, unsigned char *nsec,
                                 const unsigned char *c, unsigned long long clen, const unsigned char *ad,
                                 unsigned long long adlen, const unsigned char *npub, const unsigned char *k) {
    return crypto_aead_decrypt(m, mlen, nsec, c, clen, ad, adlen, npub, k);
}
