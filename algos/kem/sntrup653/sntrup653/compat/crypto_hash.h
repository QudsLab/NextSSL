/* NextSSL compat header (not upstream code). With NS_SUP_NAME defined (support wrapper unit) it maps crypto_hash onto that SUPERCOP lib. */
#ifdef NS_SUP_NAME
#define crypto_hash NS_SUP_NAME
#define crypto_hash_BYTES NS_SUP_PFX(BYTES)
int crypto_hash(unsigned char *,const unsigned char *,unsigned long long);
#else
/* NextSSL compat header (not upstream code): SUPERCOP prototypes. */
#ifndef NS_COMPAT_HASH
#define NS_COMPAT_HASH
#include "api.h"
int crypto_hash(unsigned char *,const unsigned char *,unsigned long long);
#ifndef crypto_hash_BYTES
#define crypto_hash_BYTES CRYPTO_BYTES
#endif
#endif
#endif
