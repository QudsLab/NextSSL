/* NextSSL compat header (not upstream code): SUPERCOP lib crypto_hashblocks_sha256 built from hashblocks_sha256/api.h (implementation ref). */
#ifndef NS_CRYPTO_HASHBLOCKS_SHA256_H
#define NS_CRYPTO_HASHBLOCKS_SHA256_H
#define crypto_hashblocks_sha256_STATEBYTES 32
#define crypto_hashblocks_sha256_BLOCKBYTES 64

#ifndef crypto_hashblocks_sha256_IMPLEMENTATION
#define crypto_hashblocks_sha256_IMPLEMENTATION "ref"
#endif
int crypto_hashblocks_sha256(unsigned char *,const unsigned char *,unsigned long long);
#endif
