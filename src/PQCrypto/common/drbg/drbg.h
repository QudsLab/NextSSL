#ifndef DRBG_H
#define DRBG_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t V[32]; /* 256 bits for HMAC-SHA256 */
    uint8_t Key[32];
    uint32_t reseed_counter;
} DRBG_CTX;

void drbg_init(DRBG_CTX *ctx, const uint8_t *seed, size_t seed_len);
void drbg_generate(DRBG_CTX *ctx, uint8_t *out, size_t out_len);
void drbg_reseed(DRBG_CTX *ctx, const uint8_t *seed, size_t seed_len);

#endif
