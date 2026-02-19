#include <stdint.h>
#include <stddef.h>

#define SHAKE256_BASE_WU 1600
#define SHAKE256_RATE 136

uint64_t dhcm_shake256_wu(size_t input_size, size_t output_size) {
    size_t num_absorptions = (input_size + SHAKE256_RATE - 1) / SHAKE256_RATE;
    if (num_absorptions == 0) num_absorptions = 1;
    
    size_t num_squeezes = 0;
    if (output_size > SHAKE256_RATE) {
        num_squeezes = (output_size - 1) / SHAKE256_RATE;
    }
    
    return SHAKE256_BASE_WU * (num_absorptions + num_squeezes);
}
