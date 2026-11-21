/* NextSSL compat header (not upstream code): SUPERCOP lib crypto_hash_sha256 built from hash_sha256/api.h (implementation ref). */
#ifndef NS_CRYPTO_HASH_SHA256_H
#define NS_CRYPTO_HASH_SHA256_H
#define crypto_hash_sha256_BYTES 32

#ifndef crypto_hash_sha256_IMPLEMENTATION
#define crypto_hash_sha256_IMPLEMENTATION "ref"
#endif
int crypto_hash_sha256(unsigned char *,const unsigned char *,unsigned long long);
#endif
