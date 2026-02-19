#include <stdint.h>
#include <stddef.h>

#define RIPEMD160_BASE_WU 1000
#define RIPEMD160_BLOCK_SIZE 64

uint64_t dhcm_ripemd160_wu(size_t input_size) {
    size_t num_blocks = 1 + (input_size / RIPEMD160_BLOCK_SIZE);
    return RIPEMD160_BASE_WU * num_blocks;
}
