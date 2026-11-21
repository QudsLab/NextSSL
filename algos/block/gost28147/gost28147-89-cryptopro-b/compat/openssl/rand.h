/* NextSSL compat header (not upstream code): gost89.c includes <openssl/rand.h> only for RAND_priv_bytes inside gost_key()
 * and magma_key() (key masking). The NextSSL glue never calls those two (it uses gost_key_nomask), so this is unreachable;
 * if it were reached it would fail (return 0) with a zeroed mask rather than draw OS randomness. */
#ifndef NS_COMPAT_OPENSSL_RAND_H
#define NS_COMPAT_OPENSSL_RAND_H
#include <stddef.h>
static int RAND_priv_bytes(unsigned char *buf, int num)
{
    int i;
    for (i = 0; i < num; i++) buf[i] = 0;
    return 0;
}
#endif
