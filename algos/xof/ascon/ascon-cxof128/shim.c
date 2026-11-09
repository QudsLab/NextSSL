#include <stddef.h>
#include "crypto_cxof.h"

/* NextSSL adapter (not upstream code): arbitrary-length output with a customization string. */
int nextssl__ascon_cxof128__xof(unsigned char *out, unsigned long long outlen, const unsigned char *in, unsigned long long inlen,
               const unsigned char *cs, unsigned long long cslen) {
    return crypto_cxof(out, outlen, in, inlen, cs, cslen);
}
