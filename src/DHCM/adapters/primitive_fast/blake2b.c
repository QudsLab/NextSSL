#include <stdint.h>
#include <stddef.h>

#define BLAKE2B_BASE_WU 800
#define BLAKE2B_BLOCK_SIZE 128
#define BLAKE2B_ROUNDS 12

uint64_t dhcm_blake2b_wu(size_t input_size) {
    size_t num_blocks = 1 + (input_size / BLAKE2B_BLOCK_SIZE);
    return BLAKE2B_BASE_WU * num_blocks;
}
