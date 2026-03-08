#include "seed_hash.h"
#include "../../primitives/hash/fast/sha512/sha512.h"
#include <string.h>

/*
 * seed_hash_derive — SHA-512 counter-mode key derivation
 *
 * output[i*64 .. (i+1)*64) = SHA-512(seed || ctx || BE32(i))
 *
 * Each 64-byte block is independent of the others given the counter suffix.
 * Final block is truncated to fill out_len exactly.
 */
int seed_hash_derive(const uint8_t *seed,   size_t seed_len,
                     const uint8_t *ctx,    size_t ctx_len,
                     uint8_t       *out,    size_t out_len) {
    if (!seed || seed_len == 0 || !out || out_len == 0) return -1;

    uint32_t ctr = 0;
    size_t   produced = 0;

    while (produced < out_len) {
        /* Build counter as 4-byte big-endian suffix */
        uint8_t ctr_bytes[4];
        ctr_bytes[0] = (uint8_t)(ctr >> 24);
        ctr_bytes[1] = (uint8_t)(ctr >> 16);
        ctr_bytes[2] = (uint8_t)(ctr >>  8);
        ctr_bytes[3] = (uint8_t)(ctr      );

        SHA512_CTX sha;
        sha512_init(&sha);
        sha512_update(&sha, seed, seed_len);
        if (ctx && ctx_len > 0)
            sha512_update(&sha, ctx, ctx_len);
        sha512_update(&sha, ctr_bytes, 4);

        uint8_t block[SHA512_DIGEST_LENGTH];
        sha512_final(block, &sha);

        size_t copy = out_len - produced;
        if (copy > SHA512_DIGEST_LENGTH) copy = SHA512_DIGEST_LENGTH;
        memcpy(out + produced, block, copy);

        /* Wipe intermediate block */
        volatile uint8_t *p = (volatile uint8_t *)block;
        for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) p[i] = 0;

        produced += copy;
        ctr++;
    }

    return 0;
}
