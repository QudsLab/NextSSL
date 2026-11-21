/* NextSSL compat header (not upstream code): gost89.c includes <openssl/crypto.h> only for OPENSSL_cleanse. */
#ifndef NS_COMPAT_OPENSSL_CRYPTO_H
#define NS_COMPAT_OPENSSL_CRYPTO_H
#include <stddef.h>
static void OPENSSL_cleanse(void *p, size_t n)
{
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}
#endif
