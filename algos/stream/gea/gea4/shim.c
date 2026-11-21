/* Shim (not crypto): one-shot wrapper over libosmocore gea3()/gea4(). Nonce = 5 bytes: the 32 bit GPRS cipher INPUT (IV,
 * big endian) followed by the direction byte (0 = MS to SGSN, 1 = SGSN to MS). The keystream is XORed into data;
 * at most 1523 bytes (GSM 04.64 maximum block). */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "osmocom/gsm/gea.h"
#include "osmocom/crypt/auth.h"
#include "osmocom/core/utils.h"

/* The helper(s) below are verbatim excerpts of src/gsm/auth_core.c (libosmocore); auth_core.c itself needs the plugin
 * registry and is not compiled. Key-format conversions only, no cipher logic. */
/* 3GPP TS 33.102 §6.8.2.3 C4 function to derive UMTS CK from GSM Kc */
void osmo_c4(uint8_t *ck, const uint8_t *kc)
{
	memcpy(ck, kc, 8);
	memcpy(ck+8, kc, 8);
}

int shim_apply(const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen,
               unsigned char *data, unsigned long len) {
    uint8_t kc[16];
    uint8_t ks[1523];
    uint32_t iv;
    unsigned long i;
    int rc = -1;
    if (keylen != NS_KEYLEN || noncelen != 5 || len > sizeof(ks)) return -1;
    if (nonce[4] > 1) return -1;
    iv = ((uint32_t)nonce[0] << 24) | ((uint32_t)nonce[1] << 16) | ((uint32_t)nonce[2] << 8) | (uint32_t)nonce[3];
    memcpy(kc, key, keylen);
    memset(ks, 0, sizeof(ks));
    if (len > 0 && NS_GEA(ks, (uint16_t)len, kc, iv, nonce[4] ? GPRS_CIPH_SGSN2MS : GPRS_CIPH_MS2SGSN) != 0) goto done;
    for (i = 0; i < len; i++) data[i] ^= ks[i];
    rc = 0;
done:
    memset(kc, 0, sizeof(kc));
    memset(ks, 0, sizeof(ks));
    return rc;
}
