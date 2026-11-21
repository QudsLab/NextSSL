/* NextSSL compat header (not upstream code): SUPERCOP prototypes. */
#ifndef NS_COMPAT_KEM
#define NS_COMPAT_KEM
#include "api.h"
int crypto_kem_keypair(unsigned char *,unsigned char *);
int crypto_kem_enc(unsigned char *,unsigned char *,const unsigned char *);
int crypto_kem_dec(unsigned char *,const unsigned char *,const unsigned char *);
#endif
