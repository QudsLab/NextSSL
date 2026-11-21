/* Shim (not crypto): one-shot wrapper over libosmocore osmo_a5(). Nonce = the GSM frame number (4 bytes, big endian,
 * 0 .. 26*51*2048-1; upstream converts it to the 22 bit COUNT). The keystream is the 114 bit downlink burst followed by
 * the 114 bit uplink burst (228 bits, packed MSB first with upstream osmo_ubit2pbit); data may use the first 28 bytes. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "osmocom/gsm/a5.h"
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
    ubit_t bits[228];
    uint8_t ks[29];
    uint32_t fn;
    unsigned long i;
    int rc = -1;
    if (keylen != NS_KEYLEN || noncelen != 4 || len > 28) return -1;
    fn = ((uint32_t)nonce[0] << 24) | ((uint32_t)nonce[1] << 16) | ((uint32_t)nonce[2] << 8) | (uint32_t)nonce[3];
    if (fn >= 26UL * 51UL * 2048UL) return -1;
    memset(bits, 0, sizeof(bits));
    memset(ks, 0, sizeof(ks));
    if (osmo_a5(NS_A5_ALGO, key, fn, bits, bits + 114) != 0) goto done;
    osmo_ubit2pbit(ks, bits, 228);
    for (i = 0; i < len; i++) data[i] ^= ks[i];
    rc = 0;
done:
    memset(bits, 0, sizeof(bits));
    memset(ks, 0, sizeof(ks));
    return rc;
}
