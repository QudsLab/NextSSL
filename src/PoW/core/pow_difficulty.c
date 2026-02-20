#include "pow_difficulty.h"
#include <string.h>

int pow_difficulty_bits_to_target(uint32_t bits, uint8_t* out_target, size_t target_len) {
    if (!out_target || target_len == 0) return -1;
    
    // Initialize to all 1s (max value)
    memset(out_target, 0xFF, target_len);
    
    // Shift right by 'bits'
    // This is effectively dividing MAX by 2^bits
    
    // Simplified:
    // Leading bytes = bits / 8
    // Leading bits in next byte = bits % 8
    
    size_t zero_bytes = bits / 8;
    size_t zero_bits = bits % 8;
    
    if (zero_bytes >= target_len) {
        memset(out_target, 0, target_len);
        return 0;
    }
    
    memset(out_target, 0, zero_bytes);
    
    if (zero_bits > 0) {
        out_target[zero_bytes] >>= zero_bits;
    }
    
    return 0;
}

int pow_difficulty_check(const uint8_t* hash, const uint8_t* target, size_t len) {
    // Compare hash < target (big endian)
    for (size_t i = 0; i < len; i++) {
        if (hash[i] < target[i]) return 1; // Less than
        if (hash[i] > target[i]) return 0; // Greater than
    }
    return 0; // Equal (usually considered valid or invalid depending on strict inequality, let's say valid if hash <= target? Task says < target)
    // If strict inequality <, then equal returns 0.
}
