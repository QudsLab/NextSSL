#include <stdint.h>
#include <stddef.h>

#define BLAKE2S_BASE_WU 700
#define BLAKE2S_BLOCK_SIZE 64
#define BLAKE2S_ROUNDS 10

uint64_t dhcm_blake2s_wu(size_t input_size) {
    size_t num_blocks = 1 + (input_size / BLAKE2S_BLOCK_SIZE);
    return BLAKE2S_BASE_WU * num_blocks;
}
