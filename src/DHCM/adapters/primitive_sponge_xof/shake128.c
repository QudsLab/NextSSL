#include <stdint.h>
#include <stddef.h>

#define SHAKE128_BASE_WU 1400
#define SHAKE128_RATE 168

uint64_t dhcm_shake128_wu(size_t input_size, size_t output_size) {
    // Absorption cost
    size_t num_absorptions = (input_size + SHAKE128_RATE - 1) / SHAKE128_RATE;
    if (num_absorptions == 0) num_absorptions = 1;
    
    // Squeezing cost
    // First block is free (part of last absorb permutation)? 
    // Usually one permutation generates 'rate' bytes.
    // So if output_size <= rate, cost is just absorption (which included one permutation).
    // If output_size > rate, we need extra permutations.
    
    size_t num_squeezes = 0;
    if (output_size > SHAKE128_RATE) {
        num_squeezes = (output_size - 1) / SHAKE128_RATE; 
        // Example: 169 bytes (rate 168). 169-1 / 168 = 1 extra squeeze.
    }
    
    return SHAKE128_BASE_WU * (num_absorptions + num_squeezes);
}
