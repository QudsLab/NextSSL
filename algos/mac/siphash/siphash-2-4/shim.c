#include <stddef.h>
#include <stdint.h>
#include "siphash.h"

/* NextSSL adapter (not upstream code): unify the upstream entry point as
 * tag(key, data, len, out, outlen) -> 0 on success. */
int nextssl__siphash_2_4__tag(const void *key, const void *data, size_t len, void *out, size_t outlen) {
    if (outlen != 8 && outlen != 16) return -1;
    return siphash(data, len, key, (uint8_t *)out, outlen) == 0 ? 0 : -1;
}
