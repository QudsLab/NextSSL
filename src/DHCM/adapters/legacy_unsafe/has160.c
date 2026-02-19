#include <stdint.h>
#include <stddef.h>

#define HAS160_BASE_WU 950
#define HAS160_BLOCK_SIZE 64

uint64_t dhcm_has160_wu(size_t input_size) {
    size_t num_blocks = 1 + (input_size / HAS160_BLOCK_SIZE);
    return HAS160_BASE_WU * num_blocks;
}
