/* noise_kdf.c — Noise Protocol HKDF (rev 34 §5.2) */
#include "noise_kdf.h"
#include "../../mac/hmac/hmac.h"
#include <string.h>

int noise_hkdf2(const uint8_t ck[NOISE_HASH_LEN],
                 const uint8_t *ikm, size_t ikm_len,
                 uint8_t out1[NOISE_HASH_LEN],
                 uint8_t out2[NOISE_HASH_LEN])
{
    if (!ck || !out1 || !out2) return -1;
    /* temp_key = HMAC-SHA256(ck, ikm) */
    uint8_t temp_key[32];
    if (hmac_compute(HMAC_SHA256, ck, NOISE_HASH_LEN,
                      ikm ? ikm : (const uint8_t *)"", ikm ? ikm_len : 0,
                      temp_key, NULL) != 0) return -1;

    /* out1 = HMAC-SHA256(temp_key, 0x01) */
    uint8_t b1 = 0x01;
    if (hmac_compute(HMAC_SHA256, temp_key, 32, &b1, 1, out1, NULL) != 0) return -1;

    /* out2 = HMAC-SHA256(temp_key, out1 || 0x02) */
    uint8_t in2[33];
    memcpy(in2, out1, 32); in2[32] = 0x02;
    if (hmac_compute(HMAC_SHA256, temp_key, 32, in2, 33, out2, NULL) != 0) return -1;

    memset(temp_key, 0, 32);
    return 0;
}

int noise_hkdf3(const uint8_t ck[NOISE_HASH_LEN],
                 const uint8_t *ikm, size_t ikm_len,
                 uint8_t out1[NOISE_HASH_LEN],
                 uint8_t out2[NOISE_HASH_LEN],
                 uint8_t out3[NOISE_HASH_LEN])
{
    if (!ck || !out1 || !out2 || !out3) return -1;

    uint8_t temp_key[32];
    if (hmac_compute(HMAC_SHA256, ck, NOISE_HASH_LEN,
                      ikm ? ikm : (const uint8_t *)"", ikm ? ikm_len : 0,
                      temp_key, NULL) != 0) return -1;

    uint8_t b1 = 0x01;
    if (hmac_compute(HMAC_SHA256, temp_key, 32, &b1, 1, out1, NULL) != 0) return -1;

    uint8_t in2[33];
    memcpy(in2, out1, 32); in2[32] = 0x02;
    if (hmac_compute(HMAC_SHA256, temp_key, 32, in2, 33, out2, NULL) != 0) return -1;

    uint8_t in3[33];
    memcpy(in3, out2, 32); in3[32] = 0x03;
    if (hmac_compute(HMAC_SHA256, temp_key, 32, in3, 33, out3, NULL) != 0) return -1;

    memset(temp_key, 0, 32);
    return 0;
}
