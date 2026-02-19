#include <stdint.h>
#include <stddef.h>

#define MD4_BASE_WU 400
#define MD4_BLOCK_SIZE 64

uint64_t dhcm_md4_wu(size_t input_size) {
    size_t num_blocks = 1 + (input_size / MD4_BLOCK_SIZE);
    return MD4_BASE_WU * num_blocks;
}
