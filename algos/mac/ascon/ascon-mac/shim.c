#include <stddef.h>
#include "crypto_auth.h"

/* NextSSL adapter (not upstream code): unify the upstream entry point as
 * tag(key, data, len, out, outlen) -> 0 on success. */
int nextssl__ascon_mac__tag(const void *key, const void *data, size_t len, void *out, size_t outlen) {
    if (outlen != 16) return -1;
    return crypto_auth((unsigned char *)out, (const unsigned char *)data, len, (const unsigned char *)key) == 0 ? 0 : -1;
}
