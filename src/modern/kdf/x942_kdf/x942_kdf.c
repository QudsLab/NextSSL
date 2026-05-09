/* x942_kdf.c — ANSI X9.42 KDF using SHA-256 */
#include "x942_kdf.h"
#include "../../../hash/sha256/sha256.h"
#include <string.h>

/* Structurally same as ConcatKDF: H(counter || Z || OtherInfo) */
int x942_kdf(const uint8_t *Z, size_t Z_len,
              const uint8_t *oi, size_t oi_len,
              uint8_t *out, size_t out_len)
{
    if (!Z || !out || out_len == 0) return -1;
    const size_t HLEN = 32;
    uint32_t counter = 1;
    size_t done = 0;

    while (done < out_len) {
        uint8_t cnt[4] = {
            (uint8_t)(counter >> 24), (uint8_t)(counter >> 16),
            (uint8_t)(counter >>  8), (uint8_t)(counter)
        };
        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, Z, Z_len);
        sha256_update(&ctx, cnt, 4);
        if (oi && oi_len) sha256_update(&ctx, oi, oi_len);
        uint8_t block[32];
        sha256_final(&ctx, block);

        size_t take = (out_len - done < HLEN) ? (out_len - done) : HLEN;
        memcpy(out + done, block, take);
        done += take;
        counter++;
    }
    return 0;
}
