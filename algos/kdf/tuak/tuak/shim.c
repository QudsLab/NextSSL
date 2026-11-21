/* Shim (not crypto): one-shot wrapper over tuak_f2345(). out = RES || CK || IK || AK (6 bytes); res/ck/ik lengths are
 * chosen by the caller (RES 4/8/16/32, CK and IK 16/32). opc = TOPc (32 bytes). */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "tuak.h"

int shim_derive(const unsigned char *topc, const unsigned char *k, unsigned long klen, const unsigned char *rnd,
                unsigned long res_len, unsigned long ck_len, unsigned long ik_len, unsigned long iters, unsigned char *out) {
    uint8_t res[32], ck[32], ik[32], ak[6];
    int rc;
    if (klen > 32 || res_len > 32 || ck_len > 32 || ik_len > 32 || iters == 0) return -1;
    rc = tuak_f2345(topc, k, (uint8_t)klen, rnd, res, (uint8_t)res_len, ck, (uint8_t)ck_len, ik, (uint8_t)ik_len, ak, (unsigned int)iters);
    if (rc == 0) {
        memcpy(out, res, res_len);
        memcpy(out + res_len, ck, ck_len);
        memcpy(out + res_len + ck_len, ik, ik_len);
        memcpy(out + res_len + ck_len + ik_len, ak, 6);
    }
    memset(res, 0, sizeof(res));
    memset(ck, 0, sizeof(ck));
    memset(ik, 0, sizeof(ik));
    memset(ak, 0, sizeof(ak));
    return rc == 0 ? 0 : -1;
}
