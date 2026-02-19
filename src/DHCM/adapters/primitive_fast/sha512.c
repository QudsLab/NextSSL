#include <stdint.h>
#include <stddef.h>

#define SHA512_BASE_WU 1200
#define SHA512_BLOCK_SIZE 128
#define SHA512_ROUNDS 80

uint64_t dhcm_sha512_wu(size_t input_size) {
    size_t num_blocks = 1 + (input_size / SHA512_BLOCK_SIZE);
    return SHA512_BASE_WU * num_blocks;
}
