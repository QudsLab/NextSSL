#include "drbg.h"
#include "../hkdf/hkdf.h"
#include <string.h>
#include <stdlib.h>

/* NIST SP 800-90A HMAC_DRBG implementation using HMAC-SHA256 */

static void drbg_update(DRBG_CTX *ctx, const uint8_t *provided_data, size_t provided_data_len) {
    uint8_t temp[32 + 1 + 256]; /* Buffer for V || 0xXX || provided_data. */
    size_t len;
    
    if (provided_data_len > 256) {
        provided_data_len = 256;
    }

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

void drbg_init(DRBG_CTX *ctx, const uint8_t *seed, size_t seed_len) {
    memset(ctx->Key, 0x00, 32);
    memset(ctx->V, 0x01, 32);
    ctx->reseed_counter = 1;
    drbg_update(ctx, seed, seed_len);
}

void drbg_reseed(DRBG_CTX *ctx, const uint8_t *seed, size_t seed_len) {
    drbg_update(ctx, seed, seed_len);
    ctx->reseed_counter = 1;
}

void drbg_generate(DRBG_CTX *ctx, uint8_t *out, size_t out_len) {
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
}
