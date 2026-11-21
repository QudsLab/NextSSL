/* NextSSL compat header (not upstream code): SUPERCOP lib crypto_hash_sha512 built from hash_sha512/api.h (implementation ref). */
#ifndef NS_CRYPTO_HASH_SHA512_H
#define NS_CRYPTO_HASH_SHA512_H
#define crypto_hash_sha512_BYTES 64

#ifndef crypto_hash_sha512_IMPLEMENTATION
#define crypto_hash_sha512_IMPLEMENTATION "ref"
#endif
int crypto_hash_sha512(unsigned char *,const unsigned char *,unsigned long long);
#endif
