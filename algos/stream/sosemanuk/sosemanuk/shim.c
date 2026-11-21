/* Shim (not crypto): one-shot wrapper over libtomcrypt sosemanuk_setup/setiv/crypt; it only calls the upstream functions. */
#include "tomcrypt.h"

int shim_apply(const unsigned char *key, unsigned long keylen, const unsigned char *iv, unsigned long ivlen, unsigned char *data, unsigned long len) {
    sosemanuk_state st;
    int rc = -1;
    if (sosemanuk_setup(&st, key, keylen) != CRYPT_OK) goto done;
    if (sosemanuk_setiv(&st, iv, ivlen) != CRYPT_OK) goto done;
    if (len > 0 && sosemanuk_crypt(&st, data, len, data) != CRYPT_OK) goto done;
    rc = 0;
done:
    zeromem(&st, sizeof(st));
    return rc;
}
