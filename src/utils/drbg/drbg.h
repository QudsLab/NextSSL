#ifndef UTILS_DRBG_H
#define UTILS_DRBG_H

#include <stdint.h>
#include <stddef.h>

/* CTR_DRBG using AES-256 */

typedef struct {
    uint8_t Key[32];
    uint8_t V[16];
    uint64_t reseed_counter;
} CTR_DRBG_CTX;

/* Initialize DRBG with entropy/seed */
void ctr_drbg_init(CTR_DRBG_CTX* ctx, const uint8_t* entropy, size_t entropy_len, const uint8_t* personalization, size_t personalization_len);

/* Reseed DRBG */
void ctr_drbg_reseed(CTR_DRBG_CTX* ctx, const uint8_t* entropy, size_t entropy_len, const uint8_t* additional, size_t additional_len);

/* Generate random bytes */
int ctr_drbg_generate(CTR_DRBG_CTX* ctx, uint8_t* out, size_t out_len, const uint8_t* additional, size_t additional_len);

/* Free/Wipe context */
void ctr_drbg_free(CTR_DRBG_CTX* ctx);

#endif
