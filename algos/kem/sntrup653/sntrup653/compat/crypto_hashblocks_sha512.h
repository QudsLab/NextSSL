/* NextSSL compat header (not upstream code): SUPERCOP lib crypto_hashblocks_sha512 built from hashblocks_sha512/api.h (implementation ref). */
#ifndef NS_CRYPTO_HASHBLOCKS_SHA512_H
#define NS_CRYPTO_HASHBLOCKS_SHA512_H
#define crypto_hashblocks_sha512_STATEBYTES 64
#define crypto_hashblocks_sha512_BLOCKBYTES 128

#ifndef crypto_hashblocks_sha512_IMPLEMENTATION
#define crypto_hashblocks_sha512_IMPLEMENTATION "ref"
#endif
int crypto_hashblocks_sha512(unsigned char *,const unsigned char *,unsigned long long);
#endif
