/* NextSSL compat header (not upstream code): SUPERCOP prototypes. */
#ifndef NS_COMPAT_HASH
#define NS_COMPAT_HASH
#include "api.h"
int crypto_hash(unsigned char *,const unsigned char *,unsigned long long);
#ifndef crypto_hash_BYTES
#define crypto_hash_BYTES CRYPTO_BYTES
#endif
#endif
