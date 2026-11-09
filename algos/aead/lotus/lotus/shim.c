#include <stddef.h>
#include "lotus-locus.h"

/* NextSSL adapter (not upstream code): dispatch on the variant index and drop the unused secret
 * nonce argument of the NIST AEAD API. Returns the upstream return code. */
typedef int (*enc_fn)(unsigned char *, unsigned long long *, const unsigned char *, unsigned long long,
                      const unsigned char *, unsigned long long, const unsigned char *, const unsigned char *,
                      const unsigned char *);
typedef int (*dec_fn)(unsigned char *, unsigned long long *, unsigned char *, const unsigned char *,
                      unsigned long long, const unsigned char *, unsigned long long, const unsigned char *,
                      const unsigned char *);


static const enc_fn ENC[] = {
    lotus_aead_encrypt
};
static const dec_fn DEC[] = {
    lotus_aead_decrypt
};

int nextssl__lotus__seal(int v, unsigned char *c, unsigned long long *clen, const unsigned char *m, unsigned long long mlen,
            const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k) {
    if (v < 0 || v >= (int)(sizeof ENC / sizeof ENC[0])) return -100;
    return ENC[v](c, clen, m, mlen, ad, adlen, NULL, npub, k);
}

int nextssl__lotus__open(int v, unsigned char *m, unsigned long long *mlen, const unsigned char *c, unsigned long long clen,
            const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k) {
    if (v < 0 || v >= (int)(sizeof DEC / sizeof DEC[0])) return -100;
    return DEC[v](m, mlen, NULL, c, clen, ad, adlen, npub, k);
}
