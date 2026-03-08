#include "drbg.h"
#include "../../PQCrypto/common/hkdf/hkdf.h"
#include <string.h>

/*
 * HMAC-DRBG using HMAC-SHA256 (NIST SP 800-90A Rev 1, Section 10.1.2)
 *
 * Canonical implementation for src/common/drbg/.
 * Migrated from src/PQCrypto/common/drbg/ and adapted with:
 *   - Updated include path for hkdf (now in ../../PQCrypto/common/hkdf/)
 *   - Strict reseed counter: drbg_generate returns -1 when limit exceeded.
 *   - drbg_wipe() added for secure erasure.
 */

/* Internal: DRBG_Update (NIST SP 800-90A Section 10.1.2.2) */
static void drbg_update(DRBG_CTX *ctx,
                        const uint8_t *provided_data,
                        size_t         provided_data_len)
{
    /* Clamp input length to 256 bytes for the temp buffer below */
    if (provided_data_len > 256) {
        provided_data_len = 256;
    }

    uint8_t temp[32 + 1 + 256];
    size_t  len;

    /* K = HMAC(K, V || 0x00 || provided_data) */
    len = 0;
    memcpy(temp + len, ctx->V, 32); len += 32;
    temp[len++] = 0x00;
    if (provided_data && provided_data_len > 0) {
        memcpy(temp + len, provided_data, provided_data_len);
        len += provided_data_len;
    }
    pqc_hmac_sha256(ctx->Key, 32, temp, len, ctx->Key);

    /* V = HMAC(K, V) */
    pqc_hmac_sha256(ctx->Key, 32, ctx->V, 32, ctx->V);

    if (provided_data && provided_data_len > 0) {
        /* K = HMAC(K, V || 0x01 || provided_data) */
        len = 0;
        memcpy(temp + len, ctx->V, 32); len += 32;
        temp[len++] = 0x01;
        memcpy(temp + len, provided_data, provided_data_len);
        len += provided_data_len;
        pqc_hmac_sha256(ctx->Key, 32, temp, len, ctx->Key);

        /* V = HMAC(K, V) */
        pqc_hmac_sha256(ctx->Key, 32, ctx->V, 32, ctx->V);
    }
}

void drbg_init(DRBG_CTX *ctx, const uint8_t *seed, size_t seed_len)
{
    memset(ctx->Key, 0x00, 32);
    memset(ctx->V,   0x01, 32);
    ctx->reseed_counter = 1;
    drbg_update(ctx, seed, seed_len);
}

void drbg_reseed(DRBG_CTX *ctx, const uint8_t *seed, size_t seed_len)
{
    drbg_update(ctx, seed, seed_len);
    ctx->reseed_counter = 1;
}

int drbg_generate(DRBG_CTX *ctx, uint8_t *out, size_t out_len)
{
    if (ctx->reseed_counter > DRBG_RESEED_LIMIT) {
        return -1; /* Caller must reseed before generating more output */
    }

    size_t generated = 0;
    while (generated < out_len) {
        /* V = HMAC(Key, V) */
        pqc_hmac_sha256(ctx->Key, 32, ctx->V, 32, ctx->V);

        size_t to_copy = (out_len - generated) > 32 ? 32 : (out_len - generated);
        memcpy(out + generated, ctx->V, to_copy);
        generated += to_copy;
    }

    drbg_update(ctx, NULL, 0);
    ctx->reseed_counter++;
    return 0;
}

void drbg_wipe(DRBG_CTX *ctx)
{
    volatile uint8_t *p = (volatile uint8_t *)ctx;
    for (size_t i = 0; i < sizeof(DRBG_CTX); i++) p[i] = 0;
}
