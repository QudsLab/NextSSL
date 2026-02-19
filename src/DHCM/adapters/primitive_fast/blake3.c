#include <stdint.h>
#include <stddef.h>

#define BLAKE3_BASE_WU 600
#define BLAKE3_BLOCK_SIZE 64
#define BLAKE3_ROUNDS 7

uint64_t dhcm_blake3_wu(size_t input_size) {
    size_t num_blocks = 1 + (input_size / BLAKE3_BLOCK_SIZE);
    return BLAKE3_BASE_WU * num_blocks;
}
