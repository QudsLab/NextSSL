#include <stdint.h>
#include <stddef.h>

#define RIPEMD320_BASE_WU 1300
#define RIPEMD320_BLOCK_SIZE 64

uint64_t dhcm_ripemd320_wu(size_t input_size) {
    size_t num_blocks = 1 + (input_size / RIPEMD320_BLOCK_SIZE);
    return RIPEMD320_BASE_WU * num_blocks;
}
