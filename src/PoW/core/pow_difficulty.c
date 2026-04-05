/* pow_difficulty.c */
#include "pow_difficulty.h"
#include <string.h>

int pow_difficulty_bits_to_target(uint32_t bits, uint8_t *out_target, size_t target_len) {
    if (!out_target || target_len == 0) return -1;

    /* Start with all-ones (maximum value) */
    memset(out_target, 0xFF, target_len);

    size_t zero_bytes = bits / 8;
    size_t zero_bits  = bits % 8;

    if (zero_bytes >= target_len) {
        memset(out_target, 0x00, target_len);
        return 0;
    }

    memset(out_target, 0x00, zero_bytes);

    if (zero_bits > 0) {
        out_target[zero_bytes] >>= zero_bits;
    }

    return 0;
}

int pow_hash_meets_target(const uint8_t *hash, const uint8_t *target, size_t len) {
    if (!hash || !target || len == 0) return 0;
    for (size_t i = 0; i < len; i++) {
        if (hash[i] < target[i]) return 1;   /* hash < target: valid */
        if (hash[i] > target[i]) return 0;   /* hash > target: invalid */
    }
    return 0;   /* equal: strict inequality requires hash < target */
}
