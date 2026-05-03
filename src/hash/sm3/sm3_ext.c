/* sm3_ext.c — sm3_final / sm3_hash wrappers over GmSSL's sm3_finish. */
#include "sm3.h"
#include <string.h>

void sm3_final(SM3_CTX *ctx, uint8_t out[SM3_DIGEST_LENGTH])
{
    sm3_finish(ctx, out);
}

void sm3_hash(const uint8_t *data, size_t datalen,
              uint8_t out[SM3_DIGEST_LENGTH])
{
    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data, datalen);
    sm3_finish(&ctx, out);
    memset(&ctx, 0, sizeof(ctx));
}
