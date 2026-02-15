#include "drbg.h"
#include "../../primitives/cipher/aes_core/aes_internal.h"
#include <string.h>

/* NIST SP 800-90A CTR_DRBG using AES-256 (df = block_cipher_df)
   Simplification: We assume we can use AES directly. 
   For full compliance, we need Derivation Function. 
   Here we implement a standard update logic without full DF for simplicity if seed is full entropy,
   but proper CTR_DRBG Update is essential.
*/

static void ctr_drbg_update(CTR_DRBG_CTX* ctx, const uint8_t* provided_data, size_t provided_data_len) {
    uint8_t temp[48]; /* 32 Key + 16 V */
    uint8_t block[16];
    size_t i;
    size_t len = 0;

    /* temp = Null */
    /* While len(temp) < seedlen (48):
         V = (V + 1) mod 2^128
         output_block = Block_Encrypt(Key, V)
         temp = temp || output_block
    */
    
    while (len < 48) {
        /* Increment V */
        for (int j = 15; j >= 0; j--) {
            if (++ctx->V[j] != 0) break;
        }

        AES_setkey(ctx->Key);
        rijndaelEncrypt(ctx->V, block);
        AES_burn();

        size_t to_copy = (48 - len) < 16 ? (48 - len) : 16;
        memcpy(temp + len, block, to_copy);
        len += to_copy;
    }

    /* temp = temp XOR provided_data */
    if (provided_data && provided_data_len > 0) {
        size_t xor_len = provided_data_len < 48 ? provided_data_len : 48;
        for (i = 0; i < xor_len; i++) {
            temp[i] ^= provided_data[i];
        }
    }

    /* Key = leftmost 32 bytes of temp */
    memcpy(ctx->Key, temp, 32);
    /* V = rightmost 16 bytes of temp */
    memcpy(ctx->V, temp + 32, 16);
}

void ctr_drbg_init(CTR_DRBG_CTX* ctx, const uint8_t* entropy, size_t entropy_len, const uint8_t* personalization, size_t personalization_len) {
    uint8_t seed_material[48] = {0};
    
    /* Default Initial Values */
    memset(ctx->Key, 0x00, 32);
    memset(ctx->V, 0x00, 16);
    ctx->reseed_counter = 0;

    /* Combine entropy and personalization simply (XOR) for seed material 
       In real usage, use a Derivation Function (Block_Cipher_DF) if inputs are not full entropy.
       Here we assume inputs are conditioned or we just XOR them.
    */
    size_t copy_len = entropy_len < 48 ? entropy_len : 48;
    memcpy(seed_material, entropy, copy_len);
    
    if (personalization) {
        size_t p_len = personalization_len < 48 ? personalization_len : 48;
        for (size_t i = 0; i < p_len; i++) {
            seed_material[i] ^= personalization[i];
        }
    }

    ctr_drbg_update(ctx, seed_material, 48);
    ctx->reseed_counter = 1;
}

void ctr_drbg_reseed(CTR_DRBG_CTX* ctx, const uint8_t* entropy, size_t entropy_len, const uint8_t* additional, size_t additional_len) {
    uint8_t seed_material[48] = {0};
    
    size_t copy_len = entropy_len < 48 ? entropy_len : 48;
    memcpy(seed_material, entropy, copy_len);
    
    if (additional) {
        size_t a_len = additional_len < 48 ? additional_len : 48;
        for (size_t i = 0; i < a_len; i++) {
            seed_material[i] ^= additional[i];
        }
    }

    ctr_drbg_update(ctx, seed_material, 48);
    ctx->reseed_counter = 1;
}

int ctr_drbg_generate(CTR_DRBG_CTX* ctx, uint8_t* out, size_t out_len, const uint8_t* additional, size_t additional_len) {
    uint8_t block[16];
    size_t generated = 0;

    if (ctx->reseed_counter > (1ULL << 48)) {
        return -1; /* Reseed required */
    }

    if (additional && additional_len > 0) {
        ctr_drbg_update(ctx, additional, additional_len);
    }

    while (generated < out_len) {
        /* Increment V */
        for (int j = 15; j >= 0; j--) {
            if (++ctx->V[j] != 0) break;
        }

        AES_setkey(ctx->Key);
        rijndaelEncrypt(ctx->V, block);
        AES_burn();

        size_t to_copy = (out_len - generated) < 16 ? (out_len - generated) : 16;
        memcpy(out + generated, block, to_copy);
        generated += to_copy;
    }

    ctr_drbg_update(ctx, additional, additional_len);
    ctx->reseed_counter++;
    return 0;
}

void ctr_drbg_free(CTR_DRBG_CTX* ctx) {
    memset(ctx, 0, sizeof(CTR_DRBG_CTX));
}
