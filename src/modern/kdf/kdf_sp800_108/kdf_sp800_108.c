/* kdf_sp800_108.c — SP 800-108 KDF (Counter, Feedback, Double-Pipeline modes)
 * PRF = HMAC-SHA256 throughout.
 */
#include "kdf_sp800_108.h"
#include "../../mac/hmac/hmac.h"
#include <string.h>

/* Build PRF input: label || 0x00 || context || L (big-endian 32-bit) */
static int build_fixed_data(const uint8_t *label, size_t label_len,
                              const uint8_t *ctx, size_t ctx_len,
                              uint32_t L_bits,
                              uint8_t *buf, size_t *buf_len)
{
    size_t need = label_len + 1 + ctx_len + 4;
    if (need > *buf_len) return -1;
    size_t pos = 0;
    if (label && label_len) { memcpy(buf + pos, label, label_len); pos += label_len; }
    buf[pos++] = 0x00;  /* separator */
    if (ctx && ctx_len) { memcpy(buf + pos, ctx, ctx_len); pos += ctx_len; }
    buf[pos++] = (uint8_t)(L_bits >> 24);
    buf[pos++] = (uint8_t)(L_bits >> 16);
    buf[pos++] = (uint8_t)(L_bits >>  8);
    buf[pos++] = (uint8_t)(L_bits);
    *buf_len = pos;
    return 0;
}

int kdf_sp800_108_counter(const uint8_t *KI, size_t KI_len,
                           const uint8_t *label, size_t label_len,
                           const uint8_t *ctx, size_t ctx_len,
                           uint8_t *out, size_t out_len)
{
    if (!KI || !out || out_len == 0) return -1;

    uint8_t fixed[512];
    size_t  fixed_len = sizeof(fixed);
    if (build_fixed_data(label, label_len, ctx, ctx_len,
                          (uint32_t)(out_len * 8), fixed, &fixed_len) != 0) return -1;

    const size_t HLEN = 32;
    size_t done = 0;
    uint32_t i = 1;

    while (done < out_len) {
        uint8_t cnt[4] = {
            (uint8_t)(i >> 24), (uint8_t)(i >> 16),
            (uint8_t)(i >>  8), (uint8_t)(i)
        };
        /* PRF input = counter || fixed_data */
        uint8_t prf_in[4 + 512];
        memcpy(prf_in, cnt, 4);
        memcpy(prf_in + 4, fixed, fixed_len);

        uint8_t block[32];
        if (hmac_compute(HMAC_SHA256, KI, KI_len,
                          prf_in, 4 + fixed_len, block, NULL) != 0) return -1;

        size_t take = (out_len - done < HLEN) ? (out_len - done) : HLEN;
        memcpy(out + done, block, take);
        done += take;
        i++;
    }
    return 0;
}

int kdf_sp800_108_feedback(const uint8_t *KI, size_t KI_len,
                            const uint8_t *IV, size_t IV_len,
                            const uint8_t *label, size_t label_len,
                            const uint8_t *ctx, size_t ctx_len,
                            uint8_t *out, size_t out_len)
{
    if (!KI || !out || out_len == 0) return -1;

    uint8_t fixed[512];
    size_t  fixed_len = sizeof(fixed);
    if (build_fixed_data(label, label_len, ctx, ctx_len,
                          (uint32_t)(out_len * 8), fixed, &fixed_len) != 0) return -1;

    const size_t HLEN = 32;
    uint8_t K_i[32] = {0};  /* K(0) = IV or zeros */
    if (IV && IV_len) {
        size_t copy = (IV_len < 32) ? IV_len : 32;
        memcpy(K_i, IV, copy);
    }

    size_t done = 0;
    uint32_t i = 1;

    while (done < out_len) {
        uint8_t cnt[4] = {
            (uint8_t)(i >> 24), (uint8_t)(i >> 16),
            (uint8_t)(i >>  8), (uint8_t)(i)
        };
        /* PRF input = K(i-1) || counter || fixed_data */
        uint8_t prf_in[32 + 4 + 512];
        memcpy(prf_in, K_i, 32);
        memcpy(prf_in + 32, cnt, 4);
        memcpy(prf_in + 36, fixed, fixed_len);

        uint8_t block[32];
        if (hmac_compute(HMAC_SHA256, KI, KI_len,
                          prf_in, 36 + fixed_len, block, NULL) != 0) return -1;
        memcpy(K_i, block, 32);

        size_t take = (out_len - done < HLEN) ? (out_len - done) : HLEN;
        memcpy(out + done, block, take);
        done += take;
        i++;
    }
    return 0;
}

int kdf_sp800_108_double_pipeline(const uint8_t *KI, size_t KI_len,
                                   const uint8_t *label, size_t label_len,
                                   const uint8_t *ctx, size_t ctx_len,
                                   uint8_t *out, size_t out_len)
{
    if (!KI || !out || out_len == 0) return -1;

    uint8_t fixed[512];
    size_t  fixed_len = sizeof(fixed);
    if (build_fixed_data(label, label_len, ctx, ctx_len,
                          (uint32_t)(out_len * 8), fixed, &fixed_len) != 0) return -1;

    const size_t HLEN = 32;
    uint8_t A_i[32];

    /* A(0) = fixed_data; A(i) = PRF(KI, A(i-1)) */
    if (hmac_compute(HMAC_SHA256, KI, KI_len, fixed, fixed_len, A_i, NULL) != 0) return -1;

    size_t done = 0;
    uint32_t i = 1;

    while (done < out_len) {
        uint8_t cnt[4] = {
            (uint8_t)(i >> 24), (uint8_t)(i >> 16),
            (uint8_t)(i >>  8), (uint8_t)(i)
        };
        /* K(i) = PRF(KI, A(i) || counter || fixed_data) */
        uint8_t prf_in[32 + 4 + 512];
        memcpy(prf_in, A_i, 32);
        memcpy(prf_in + 32, cnt, 4);
        memcpy(prf_in + 36, fixed, fixed_len);

        uint8_t block[32];
        if (hmac_compute(HMAC_SHA256, KI, KI_len,
                          prf_in, 36 + fixed_len, block, NULL) != 0) return -1;

        size_t take = (out_len - done < HLEN) ? (out_len - done) : HLEN;
        memcpy(out + done, block, take);
        done += take;
        i++;

        /* Advance A pipeline for next round */
        if (done < out_len) {
            if (hmac_compute(HMAC_SHA256, KI, KI_len, A_i, 32, A_i, NULL) != 0) return -1;
        }
    }
    return 0;
}
