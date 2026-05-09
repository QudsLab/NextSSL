/* kda_onestep.c — KDA One-Step (SP 800-56C Rev 2 §4) */
#include "kda_onestep.h"
#include "../../../hash/sha256/sha256.h"
#include "../../mac/hmac/hmac.h"
#include <string.h>

int kda_onestep_hash(const uint8_t *Z, size_t Z_len,
                      const uint8_t *fi, size_t fi_len,
                      uint8_t *out, size_t out_len)
{
    if (!Z || !out || out_len == 0) return -1;
    const size_t HLEN = 32;
    uint32_t counter = 1;
    size_t done = 0;

    while (done < out_len) {
        uint8_t cnt[4] = {
            (uint8_t)(counter >> 24), (uint8_t)(counter >> 16),
            (uint8_t)(counter >> 8),  (uint8_t)(counter)
        };
        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, cnt, 4);
        sha256_update(&ctx, Z, Z_len);
        if (fi && fi_len) sha256_update(&ctx, fi, fi_len);
        uint8_t block[32];
        sha256_final(&ctx, block);

        size_t take = (out_len - done < HLEN) ? (out_len - done) : HLEN;
        memcpy(out + done, block, take);
        done += take;
        counter++;
    }
    return 0;
}

int kda_onestep_hmac(const uint8_t *Z, size_t Z_len,
                      const uint8_t *salt, size_t salt_len,
                      const uint8_t *fi, size_t fi_len,
                      uint8_t *out, size_t out_len)
{
    if (!Z || !out || out_len == 0) return -1;
    /* Default salt: 32 zero bytes */
    static const uint8_t ZERO_SALT[32] = {0};
    if (!salt || salt_len == 0) { salt = ZERO_SALT; salt_len = 32; }

    const size_t HLEN = 32;
    uint32_t counter = 1;
    size_t done = 0;

    while (done < out_len) {
        uint8_t cnt[4] = {
            (uint8_t)(counter >> 24), (uint8_t)(counter >> 16),
            (uint8_t)(counter >> 8),  (uint8_t)(counter)
        };
        /* HMAC input = counter || Z || FixedInfo */
        uint8_t hmac_in[4 + 256 + 256];
        size_t hlen = 0;
        memcpy(hmac_in + hlen, cnt, 4);   hlen += 4;
        memcpy(hmac_in + hlen, Z, Z_len); hlen += Z_len;
        if (fi && fi_len && hlen + fi_len <= sizeof(hmac_in)) {
            memcpy(hmac_in + hlen, fi, fi_len); hlen += fi_len;
        }

        uint8_t block[32];
        if (hmac_compute(HMAC_SHA256, salt, salt_len,
                          hmac_in, hlen, block, NULL) != 0) return -1;

        size_t take = (out_len - done < HLEN) ? (out_len - done) : HLEN;
        memcpy(out + done, block, take);
        done += take;
        counter++;
    }
    return 0;
}
