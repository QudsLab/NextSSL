/* Shim (not crypto): one-shot wrapper over milenage_f2345(). out = RES (8) || CK (16) || IK (16) || AK (6) = 46 bytes. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "osmocom/crypt/auth.h"
#include "osmocom/core/utils.h"

int milenage_f2345(const uint8_t *opc, const uint8_t *k, const uint8_t *_rand, uint8_t *res, uint8_t *ck, uint8_t *ik, uint8_t *ak, uint8_t *akstar);

/* The helper(s) below are verbatim excerpts of src/gsm/auth_core.c (libosmocore); auth_core.c itself needs the plugin
 * registry and is not compiled. Key-format conversions only, no cipher logic. */
void osmo_auth_c3(uint8_t kc[], const uint8_t ck[], const uint8_t ik[])
{
	int i;
	for (i = 0; i < 8; i++)
		kc[i] = ck[i] ^ ck[i + 8] ^ ik[i] ^ ik[i + 8];
}

void osmo_auth_c2(uint8_t sres[4], const uint8_t *res, size_t res_len, uint8_t sres_deriv_func)
{
	uint8_t xres[16];

	OSMO_ASSERT(sres_deriv_func == 1 || sres_deriv_func == 2);
	OSMO_ASSERT(res_len <= sizeof(xres));

	memcpy(xres, res, res_len);

	/* zero-pad the end, if XRES is < 16 bytes */
	if (res_len < sizeof(xres))
		memset(xres+res_len, 0, sizeof(xres)-res_len);

	if (sres_deriv_func == 1) {
		/* SRES derivation function #1 */
		for (unsigned int i = 0; i < 4; i++)
			sres[i] = xres[i] ^ xres[4+i] ^ xres[8+i] ^ xres[12+i];
	} else {
		/* SRES derivation function #2 */
		memcpy(sres, xres, 4);
	}
}

int shim_derive(const unsigned char *k, const unsigned char *rnd, const unsigned char *opc, unsigned char *out) {
    uint8_t res[8], ck[16], ik[16], ak[6];
    int rc = milenage_f2345(opc, k, rnd, res, ck, ik, ak, NULL);
    if (rc == 0) {
        memcpy(out, res, 8);
        memcpy(out + 8, ck, 16);
        memcpy(out + 24, ik, 16);
        memcpy(out + 40, ak, 6);
    }
    memset(res, 0, sizeof(res));
    memset(ck, 0, sizeof(ck));
    memset(ik, 0, sizeof(ik));
    memset(ak, 0, sizeof(ak));
    return rc == 0 ? 0 : -1;
}
