/* Generated shim (not crypto): one-shot wrapper over libtomcrypt sober128_stream_*; it only calls the upstream functions. */
#include "tomcrypt.h"

int shim_apply(const unsigned char *key, int keylen, const unsigned char *iv, int ivlen, unsigned char *data, unsigned int len) {
    sober128_state st;
    int rc = -1;
    if (sober128_stream_setup(&st, key, (unsigned long)keylen) != CRYPT_OK) goto done;
    if (sober128_stream_setiv(&st, iv, (unsigned long)ivlen) != CRYPT_OK) goto done;
    if (len > 0 && sober128_stream_crypt(&st, data, (unsigned long)len, data) != CRYPT_OK) goto done;
    rc = 0;
done:
    zeromem(&st, sizeof(st));
    return rc;
}
