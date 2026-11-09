#include <stddef.h>
#include "crypto_auth.h"
int crypto_prf(unsigned char *out, unsigned long long outlen, const unsigned char *in, unsigned long long inlen, const unsigned char *k);

/* NextSSL adapter (not upstream code): unify the upstream entry point as
 * tag(key, data, len, out, outlen) -> 0 on success. */
int nextssl__ascon_prf__tag(const void *key, const void *data, size_t len, void *out, size_t outlen) {
    if (outlen == 0 || outlen > 64) return -1;
    return crypto_prf((unsigned char *)out, outlen, (const unsigned char *)data, len, (const unsigned char *)key) == 0 ? 0 : -1;
}
