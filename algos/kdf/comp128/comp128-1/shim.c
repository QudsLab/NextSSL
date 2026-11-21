/* Shim (not crypto): one-shot wrapper over libosmocore comp128v1/v2/v3. out = SRES (4 bytes) || Kc (8 bytes). */
#include <stdint.h>
#include <string.h>
#include "osmocom/gsm/comp128.h"

int shim_derive(const unsigned char *ki, const unsigned char *rnd, unsigned char *out) {
    uint8_t sres[4], kc[8];
    int rc = 0;
    comp128v1(ki, rnd, sres, kc);
    if (rc == 0) {
        memcpy(out, sres, 4);
        memcpy(out + 4, kc, 8);
    }
    memset(sres, 0, sizeof(sres));
    memset(kc, 0, sizeof(kc));
    return rc == 0 ? 0 : -1;
}
