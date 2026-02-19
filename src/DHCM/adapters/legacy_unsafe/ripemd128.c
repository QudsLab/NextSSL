#include <stdint.h>
#include <stddef.h>

#define RIPEMD128_BASE_WU 800
#define RIPEMD128_BLOCK_SIZE 64

uint64_t dhcm_ripemd128_wu(size_t input_size) {
    size_t num_blocks = 1 + (input_size / RIPEMD128_BLOCK_SIZE);
    return RIPEMD128_BASE_WU * num_blocks;
}
