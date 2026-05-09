/* concat_kdf.c — ConcatKDF / NIST SP 800-56C Single-Step KDF */
#include "concat_kdf.h"
#include "../../../hash/sha256/sha256.h"
#include "../../../hash/sha384/sha384.h"
#include <string.h>

/* Alias: identical algorithm to ansi_x963_kdf with OtherInfo replacing SharedInfo */
static int concat_kdf_inner(const uint8_t *Z, size_t Z_len,
                              const uint8_t *oi, size_t oi_len,
                              uint8_t *out, size_t out_len, int sha384)
{
    if (!Z || !out || out_len == 0) return -1;
    const size_t HLEN = sha384 ? 48 : 32;
    uint32_t counter = 1;
    size_t done = 0;

    while (done < out_len) {
        uint8_t cnt[4] = {
            (uint8_t)(counter >> 24), (uint8_t)(counter >> 16),
            (uint8_t)(counter >> 8),  (uint8_t)(counter)
        };
        uint8_t block[48];
        if (sha384) {
            sha384_ctx ctx;
            sha384_init(&ctx);
            sha384_update(&ctx, cnt, 4);
            sha384_update(&ctx, Z, Z_len);
            if (oi && oi_len) sha384_update(&ctx, oi, oi_len);
            sha384_final(&ctx, block);
        } else {
            sha256_ctx ctx;
            sha256_init(&ctx);
            sha256_update(&ctx, cnt, 4);
            sha256_update(&ctx, Z, Z_len);
            if (oi && oi_len) sha256_update(&ctx, oi, oi_len);
            sha256_final(&ctx, block);
        }
        size_t take = (out_len - done < HLEN) ? (out_len - done) : HLEN;
        memcpy(out + done, block, take);
        done += take;
        counter++;
    }
    return 0;
}

int concat_kdf(const uint8_t *Z, size_t Z_len,
               const uint8_t *oi, size_t oi_len,
               uint8_t *out, size_t out_len)
{
    return concat_kdf_inner(Z, Z_len, oi, oi_len, out, out_len, 0);
}

int concat_kdf_sha384(const uint8_t *Z, size_t Z_len,
                       const uint8_t *oi, size_t oi_len,
                       uint8_t *out, size_t out_len)
{
    return concat_kdf_inner(Z, Z_len, oi, oi_len, out, out_len, 1);
}
