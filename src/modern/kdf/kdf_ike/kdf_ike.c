/* kdf_ike.c — IKEv2 Key Derivation (RFC 7296 §2.13) using HMAC-SHA256 */
#include "kdf_ike.h"
#include "../../mac/hmac/hmac.h"
#include <string.h>

int ike_skeyseed(const uint8_t *Ni, size_t Ni_len,
                  const uint8_t *Nr, size_t Nr_len,
                  const uint8_t *g_ir, size_t g_ir_len,
                  uint8_t skeyseed[IKE_SKEYSEED_SIZE])
{
    if (!Ni || !Nr || !g_ir || !skeyseed) return -1;

    /* PRF key = Ni | Nr */
    uint8_t prf_key[512];
    if (Ni_len + Nr_len > sizeof(prf_key)) return -1;
    memcpy(prf_key, Ni, Ni_len);
    memcpy(prf_key + Ni_len, Nr, Nr_len);

    return hmac_compute(HMAC_SHA256, prf_key, Ni_len + Nr_len,
                         g_ir, g_ir_len, skeyseed, NULL);
}

int ike_prf_plus(const uint8_t *K, size_t K_len,
                  const uint8_t *S, size_t S_len,
                  uint8_t *out, size_t out_len)
{
    if (!K || !S || !out || out_len == 0) return -1;

    const size_t HLEN = 32;
    uint8_t T[32] = {0};
    size_t done = 0;
    uint8_t ctr = 1;

    while (done < out_len) {
        /* T(i) = prf(K, T(i-1) | S | i) */
        uint8_t prf_in[32 + 512 + 1];
        size_t pos = 0;
        if (done > 0) { memcpy(prf_in + pos, T, HLEN); pos += HLEN; }
        if (S_len > 512) return -1;
        memcpy(prf_in + pos, S, S_len); pos += S_len;
        prf_in[pos++] = ctr;

        if (hmac_compute(HMAC_SHA256, K, K_len, prf_in, pos, T, NULL) != 0) return -1;

        size_t take = (out_len - done < HLEN) ? (out_len - done) : HLEN;
        memcpy(out + done, T, take);
        done += take;
        ctr++;
    }
    return 0;
}

int ike_key_material(const uint8_t  skeyseed[IKE_SKEYSEED_SIZE],
                      const uint8_t *Ni, size_t Ni_len,
                      const uint8_t *Nr, size_t Nr_len,
                      const uint8_t  SPIi[IKE_SPI_SIZE],
                      const uint8_t  SPIr[IKE_SPI_SIZE],
                      uint8_t *key_mat, size_t key_mat_len)
{
    if (!skeyseed || !Ni || !Nr || !SPIi || !SPIr || !key_mat) return -1;

    /* S = Ni | Nr | SPIi | SPIr */
    uint8_t S[512 + 512 + 8 + 8];
    if (Ni_len + Nr_len + 16 > sizeof(S)) return -1;
    size_t pos = 0;
    memcpy(S + pos, Ni,   Ni_len); pos += Ni_len;
    memcpy(S + pos, Nr,   Nr_len); pos += Nr_len;
    memcpy(S + pos, SPIi, 8);      pos += 8;
    memcpy(S + pos, SPIr, 8);      pos += 8;

    return ike_prf_plus(skeyseed, IKE_SKEYSEED_SIZE, S, pos, key_mat, key_mat_len);
}
