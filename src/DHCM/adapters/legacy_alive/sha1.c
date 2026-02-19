#include <stdint.h>
#include <stddef.h>

#define SHA1_BASE_WU 900
#define SHA1_BLOCK_SIZE 64

uint64_t dhcm_sha1_wu(size_t input_size) {
    size_t num_blocks = 1 + (input_size / SHA1_BLOCK_SIZE);
    return SHA1_BASE_WU * num_blocks;
}
