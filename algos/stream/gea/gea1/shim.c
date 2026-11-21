/* Shim (not crypto): one-shot wrapper over gea1()/gea2() of P1sec gea12.c. Nonce = 5 bytes: the 32 bit IV exactly as upstream
 * GEAInput.iv (4 bytes) followed by the direction byte GEAInput.dir (0 uplink, 1 downlink; anything else is refused).
 * The keystream is XORed into data; at most 1523 bytes (GSM 04.64 maximum block). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "gea12.h"

int shim_apply(const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen,
               unsigned char *data, unsigned long len) {
    GEAInput in;
    GEAOutput out;
    uint8_t ks[1523];
    unsigned long i;
    int rc = -1;
    if (keylen != 8 || noncelen != 5 || len > sizeof(ks) || nonce[4] > 1) return -1;
    memset(&in, 0, sizeof(in));
    memset(ks, 0, sizeof(ks));
    memcpy(in.iv, nonce, 4);
    in.dir = nonce[4];
    memcpy(in.key, key, 8);
    out.len = (int)len;
    out.ks = ks;
    if (len > 0) {
        NS_GEA(&in, &out);
        for (i = 0; i < len; i++) data[i] ^= ks[i];
    }
    rc = 0;
    memset(&in, 0, sizeof(in));
    memset(ks, 0, sizeof(ks));
    return rc;
}
