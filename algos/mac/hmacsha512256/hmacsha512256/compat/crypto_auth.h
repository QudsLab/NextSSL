/* NextSSL compat header (not upstream code): SUPERCOP prototypes. */
#ifndef NS_COMPAT_AUTH
#define NS_COMPAT_AUTH
#include "api.h"
int crypto_auth(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
int crypto_auth_verify(const unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
#ifndef crypto_auth_BYTES
#define crypto_auth_BYTES CRYPTO_BYTES
#endif
#ifndef crypto_auth_KEYBYTES
#define crypto_auth_KEYBYTES CRYPTO_KEYBYTES
#endif
#endif
