/* NextSSL compat header (not upstream code): SUPERCOP prototypes. */
#ifndef NS_COMPAT_SIGN
#define NS_COMPAT_SIGN
#include "api.h"
int crypto_sign_keypair(unsigned char *,unsigned char *);
int crypto_sign(unsigned char *,unsigned long long *,const unsigned char *,unsigned long long,const unsigned char *);
int crypto_sign_open(unsigned char *,unsigned long long *,const unsigned char *,unsigned long long,const unsigned char *);
#endif
