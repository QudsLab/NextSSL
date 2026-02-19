#include <stdint.h>
#include <stddef.h>

#define RIPEMD256_BASE_WU 1100
#define RIPEMD256_BLOCK_SIZE 64

uint64_t dhcm_ripemd256_wu(size_t input_size) {
    size_t num_blocks = 1 + (input_size / RIPEMD256_BLOCK_SIZE);
    return RIPEMD256_BASE_WU * num_blocks;
}
