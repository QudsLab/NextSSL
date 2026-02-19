#include <stdint.h>
#include <stddef.h>

#define MD5_BASE_WU 500
#define MD5_BLOCK_SIZE 64

uint64_t dhcm_md5_wu(size_t input_size) {
    size_t num_blocks = 1 + (input_size / MD5_BLOCK_SIZE);
    return MD5_BASE_WU * num_blocks;
}
