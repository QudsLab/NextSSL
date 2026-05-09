/* kdf_ssh.c — SSH Key Derivation (RFC 4253 §7.2) using SHA-256 */
#include "kdf_ssh.h"
#include "../../../hash/sha256/sha256.h"
#include <string.h>

int ssh_kdf(const uint8_t *K,          size_t K_len,
            const uint8_t *H,          size_t H_len,
            const uint8_t *session_id, size_t sid_len,
            uint8_t        purpose,
            uint8_t       *out,        size_t out_len)
{
    if (!K || !H || !session_id || !out || out_len == 0) return -1;

    /* SHA-256 output = 32 bytes */
    const size_t HLEN = 32;
    uint8_t block[32];
    size_t done = 0;

    /* First block: HASH(K || H || purpose || session_id) */
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, K, K_len);
    sha256_update(&ctx, H, H_len);
    sha256_update(&ctx, &purpose, 1);
    sha256_update(&ctx, session_id, sid_len);
    sha256_final(&ctx, block);

    size_t take = (out_len < HLEN) ? out_len : HLEN;
    memcpy(out, block, take);
    done += take;

    /* Additional blocks: HASH(K || H || previous_output) */
    while (done < out_len) {
        sha256_init(&ctx);
        sha256_update(&ctx, K, K_len);
        sha256_update(&ctx, H, H_len);
        sha256_update(&ctx, out, done);  /* all output so far */
        sha256_final(&ctx, block);

        take = (out_len - done < HLEN) ? (out_len - done) : HLEN;
        memcpy(out + done, block, take);
        done += take;
    }

    memset(block, 0, sizeof(block));
    return 0;
}
