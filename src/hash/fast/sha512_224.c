/* sha512_224.c — SHA-512/224 (FIPS 180-4 §5.3.6.1)
 *
 * Initial hash values are the first 224 bits of the fractional parts of the
 * square roots of the 23rd through 38th prime numbers, obtained by running
 * SHA-512 as described in FIPS 180-4 §5.3.6.1.
 *
 * All compression work is delegated to sha512_update / sha512_transform;
 * only the IVs and output truncation differ from SHA-512.
 */
#include "sha512_224.h"
#include <string.h>

/* FIPS 180-4 §5.3.6.1 — SHA-512/224 initial hash values */
void sha512_224_init(SHA512_224_CTX *ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0x8C3D37C819544DA2ULL;
    ctx->state[1] = 0x73E1996689DCD4D6ULL;
    ctx->state[2] = 0x1DFAB7AE32FF9C82ULL;
    ctx->state[3] = 0x679DD514582F9FCFULL;
    ctx->state[4] = 0x0F6D2B697BD44DA8ULL;
    ctx->state[5] = 0x77E36F7304C48942ULL;
    ctx->state[6] = 0x3F9D85A86A1D36C8ULL;
    ctx->state[7] = 0x1112E6AD91D692A1ULL;
}

/* sha512_update is shared — no separate definition needed here */

void sha512_224_final(uint8_t digest[SHA512_224_DIGEST_LENGTH], SHA512_224_CTX *ctx) {
    uint8_t full[SHA512_DIGEST_LENGTH];
    sha512_final(full, ctx);              /* produces 64 bytes, wipes ctx */
    memcpy(digest, full, SHA512_224_DIGEST_LENGTH);
    memset(full, 0, sizeof(full));        /* wipe the unused tail */
}

void sha512_224_hash(const uint8_t *data, size_t len,
                     uint8_t digest[SHA512_224_DIGEST_LENGTH]) {
    SHA512_224_CTX ctx;
    sha512_224_init(&ctx);
    sha512_update(&ctx, data, len);
    sha512_224_final(digest, &ctx);
}
