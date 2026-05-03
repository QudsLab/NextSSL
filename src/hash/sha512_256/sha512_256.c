/* sha512_256.c — SHA-512/256 (FIPS 180-4 §5.3.6.2)
 *
 * Initial hash values obtained by running SHA-512 with a modified IV as
 * specified in FIPS 180-4 §5.3.6.2.
 */
#include "sha512_256.h"
#include <string.h>

/* FIPS 180-4 §5.3.6.2 — SHA-512/256 initial hash values */
void sha512_256_init(SHA512_256_CTX *ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0x22312194FC2BF72CULL;
    ctx->state[1] = 0x9F555FA3C84C64C2ULL;
    ctx->state[2] = 0x2393B86B6F53B151ULL;
    ctx->state[3] = 0x963877195940EABDULL;
    ctx->state[4] = 0x96283EE2A88EFFE3ULL;
    ctx->state[5] = 0xBE5E1E2553863992ULL;
    ctx->state[6] = 0x2B0199FC2C85B8AAULL;
    ctx->state[7] = 0x0EB72DDC81C52CA2ULL;
}

void sha512_256_final(uint8_t digest[SHA512_256_DIGEST_LENGTH], SHA512_256_CTX *ctx) {
    uint8_t full[SHA512_DIGEST_LENGTH];
    sha512_final(full, ctx);
    memcpy(digest, full, SHA512_256_DIGEST_LENGTH);
    memset(full, 0, sizeof(full));
}

void sha512_256_hash(const uint8_t *data, size_t len,
                     uint8_t digest[SHA512_256_DIGEST_LENGTH]) {
    SHA512_256_CTX ctx;
    sha512_256_init(&ctx);
    sha512_update(&ctx, data, len);
    sha512_256_final(digest, &ctx);
}
