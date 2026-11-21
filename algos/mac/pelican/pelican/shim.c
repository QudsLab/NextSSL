/* Shim (not crypto): one-shot wrapper over libtomcrypt pelican_init/process/done; it only calls the upstream functions. */
#include "tomcrypt.h"

int shim_tag(const unsigned char *key, unsigned long keylen, const unsigned char *data, unsigned long len, unsigned char *out) {
    pelican_state st;
    int rc = -1;
    if (pelican_init(&st, key, keylen) != CRYPT_OK) goto done;
    if (len > 0 && pelican_process(&st, data, len) != CRYPT_OK) goto done;
    if (pelican_done(&st, out) != CRYPT_OK) goto done;
    rc = 0;
done:
    zeromem(&st, sizeof(st));
    return rc;
}
