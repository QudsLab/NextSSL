/* NextSSL compat header (not upstream code): hash.c includes <openssl/sha.h> for SHA256() / SHA512(). There is no OpenSSL here;
 * shim.c defines these two one-shot functions on top of liboqs' plain C SHA-2 (copied verbatim under upstream/liboqs/). */
#ifndef NS_OPENSSL_SHA_H
#define NS_OPENSSL_SHA_H
#include <stddef.h>
unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *SHA512(const unsigned char *d, size_t n, unsigned char *md);
#endif
