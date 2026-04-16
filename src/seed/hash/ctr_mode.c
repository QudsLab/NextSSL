/* ctr_mode.c — CTR-Mode Expansion Implementation */
#include "ctr_mode.h"
#include "hash_internal.h"
#include "../../hash/interface/hash_ops.h"
#include "../../common/secure_zero.h"
#include <string.h>
#include <stdio.h>

/* -------------------------------------------------------------------------
 * ctr_mode_expand — CTR-mode hash expansion
 * -------------------------------------------------------------------------*/
int ctr_mode_expand(const hash_ops_t *engine,
                    const uint8_t *seed, size_t seed_len,
                    const char *ctx_label, size_t ctx_label_len,
                    uint8_t *out, size_t out_len)
{
    uint8_t ctx_buffer[HASH_OPS_CTX_MAX];
    uint8_t block[HASH_OPS_MAX_BLOCK];
    uint32_t counter;
    size_t bytes_generated;
    size_t bytes_to_copy;

    /* Validate inputs */
    if (!engine || !out || out_len == 0 || out_len > SEED_MAX_OUTPUT_LEN) {
        return -1;
    }
    if (seed_len > 0 && !seed) {
        return -1;
    }
    if (ctx_label_len > 0 && !ctx_label) {
        return -1;
    }

    /* Validate context label length */
    if (ctx_label_len > SEED_MAX_LABEL_LEN) {
        return -1;
    }

    /* Initialize counter */
    counter = SEED_CTR_START;
    bytes_generated = 0;

    /* CTR-mode expansion loop */
    while (bytes_generated < out_len) {
        uint8_t counter_bytes[SEED_CTR_SIZE];

        /* Convert counter to big-endian */
        counter_bytes[0] = (uint8_t)((counter >> 24) & 0xFF);
        counter_bytes[1] = (uint8_t)((counter >> 16) & 0xFF);
        counter_bytes[2] = (uint8_t)((counter >> 8) & 0xFF);
        counter_bytes[3] = (uint8_t)(counter & 0xFF);

        /* Initialize hash context */
        engine->init(ctx_buffer);

        /* Hash(seed || ctx_label || counter) */
        if (seed_len > 0) {
            engine->update(ctx_buffer, seed, seed_len);
        }
        if (ctx_label_len > 0) {
            engine->update(ctx_buffer, (const uint8_t *)ctx_label, ctx_label_len);
        }
        engine->update(ctx_buffer, counter_bytes, SEED_CTR_SIZE);

        /* Finalize hash block */
        engine->final(ctx_buffer, block);

        /* Copy block to output, truncating as needed */
        bytes_to_copy = (out_len - bytes_generated);
        if (bytes_to_copy > engine->digest_size) {
            bytes_to_copy = engine->digest_size;
        }

        memcpy(out + bytes_generated, block, bytes_to_copy);
        bytes_generated += bytes_to_copy;
        counter++;
    }

    /* Secure wipe temporary buffers */
    secure_zero(ctx_buffer, sizeof(ctx_buffer));
    secure_zero(block, sizeof(block));

    return 0;
}
