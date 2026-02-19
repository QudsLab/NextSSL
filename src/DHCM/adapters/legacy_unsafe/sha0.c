#include <stdint.h>
#include <stddef.h>

#define SHA0_BASE_WU 900
#define SHA0_BLOCK_SIZE 64

uint64_t dhcm_sha0_wu(size_t input_size) {
    size_t num_blocks = 1 + (input_size / SHA0_BLOCK_SIZE);
    return SHA0_BASE_WU * num_blocks;
}
