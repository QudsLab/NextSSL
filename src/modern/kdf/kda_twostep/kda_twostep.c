/* kda_twostep.c — KDA Two-Step (SP 800-56C Rev 2 §5) via HKDF */
#include "kda_twostep.h"
#include "../hkdf/hkdf.h"
#include <string.h>

int kda_twostep(const uint8_t *Z,   size_t Z_len,
                const uint8_t *salt, size_t salt_len,
                const uint8_t *fi,   size_t fi_len,
                uint8_t *out,        size_t out_len)
{
    if (!Z || !out || out_len == 0) return -1;
    /* Step 1: PRK = HKDF-Extract(salt, Z) */
    uint8_t prk[32];
    if (hkdf_extract_ex(NULL, salt, salt_len, Z, Z_len, prk) != 0) return -1;
    /* Step 2: OKM = HKDF-Expand(PRK, FixedInfo, L) */
    return hkdf_expand_ex(NULL, prk, 32, fi, fi_len, out, out_len);
}
