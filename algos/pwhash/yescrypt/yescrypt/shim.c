#include <stddef.h>
#include <stdint.h>
#include "yescrypt.h"

/* NextSSL adapter (not upstream code): yescrypt_kdf with YESCRYPT_DEFAULTS flags, no ROM, g = 0.
 * Returns 0 on success. The thread-local region is freed (yescrypt wipes it) before return. */
int nextssl__yescrypt__kdf(const void *pw, size_t pwlen, const void *salt, size_t saltlen,
          uint32_t ln, uint32_t r, uint32_t p, uint32_t t, void *out, size_t outlen) {
    yescrypt_local_t local;
    yescrypt_params_t params;
    int rc;
    if (ln < 1 || ln > 40) return -1;
    params.flags = YESCRYPT_DEFAULTS;
    params.N = (uint64_t)1 << ln;
    params.r = r;
    params.p = p;
    params.t = t;
    params.g = 0;
    params.NROM = 0;
    if (yescrypt_init_local(&local)) return -1;
    rc = yescrypt_kdf(NULL, &local, (const uint8_t *)pw, pwlen, (const uint8_t *)salt, saltlen,
                      &params, (uint8_t *)out, outlen);
    if (yescrypt_free_local(&local)) rc = -1;
    return rc ? -1 : 0;
}
