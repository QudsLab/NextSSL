#include <stdint.h>
#include <stddef.h>

#define WHIRLPOOL_BASE_WU 2000
#define WHIRLPOOL_BLOCK_SIZE 64

uint64_t dhcm_whirlpool_wu(size_t input_size) {
    size_t num_blocks = 1 + (input_size / WHIRLPOOL_BLOCK_SIZE);
    return WHIRLPOOL_BASE_WU * num_blocks;
}
