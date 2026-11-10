/* NextSSL compat header (not upstream code): SUPERCOP prototypes. */
#ifndef NS_COMPAT_STREAM
#define NS_COMPAT_STREAM
#include "api.h"
int crypto_stream(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
int crypto_stream_xor(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
#endif
