/* kdf_ansi_x963.c — ANSI X9.63 KDF using SHA-256 */
#include "kdf_ansi_x963.h"
#include "../../../hash/sha256/sha256.h"
#include "../../../hash/sha384/sha384.h"
#include <string.h>

static int x963_kdf_inner(const uint8_t *Z, size_t Z_len,
                           const uint8_t *si, size_t si_len,
                           uint8_t *out, size_t out_len, int use_sha384)
{
    if (!Z || !out || out_len == 0) return -1;
    const size_t HLEN = use_sha384 ? 48 : 32;
    uint32_t counter = 1;
    size_t done = 0;

    while (done < out_len) {
        uint8_t cnt[4] = {
            (uint8_t)(counter >> 24), (uint8_t)(counter >> 16),
            (uint8_t)(counter >> 8),  (uint8_t)(counter)
        };
        uint8_t block[48];
        if (use_sha384) {
            sha384_ctx ctx;
            sha384_init(&ctx);
            sha384_update(&ctx, Z, Z_len);
            sha384_update(&ctx, cnt, 4);
            if (si && si_len) sha384_update(&ctx, si, si_len);
            sha384_final(&ctx, block);
        } else {
            sha256_ctx ctx;
            sha256_init(&ctx);
            sha256_update(&ctx, Z, Z_len);
            sha256_update(&ctx, cnt, 4);
            if (si && si_len) sha256_update(&ctx, si, si_len);
            sha256_final(&ctx, block);
        }
        size_t take = (out_len - done < HLEN) ? (out_len - done) : HLEN;
        memcpy(out + done, block, take);
        done += take;
        counter++;
    }
    return 0;
}

int ansi_x963_kdf(const uint8_t *Z, size_t Z_len,
                   const uint8_t *si, size_t si_len,
                   uint8_t *out, size_t out_len)
{
    return x963_kdf_inner(Z, Z_len, si, si_len, out, out_len, 0);
}

int ansi_x963_kdf_sha384(const uint8_t *Z, size_t Z_len,
                          const uint8_t *si, size_t si_len,
                          uint8_t *out, size_t out_len)
{
    return x963_kdf_inner(Z, Z_len, si, si_len, out, out_len, 1);
}
