#include <stdint.h>
#include <stddef.h>

#define SHA256_BASE_WU 1000
#define SHA256_BLOCK_SIZE 64
#define SHA256_ROUNDS 64

uint64_t dhcm_sha256_wu(size_t input_size) {
    // Number of blocks (including padding block)
    // Simple model: at least 1 block, plus every 64 bytes adds a block
    size_t num_blocks = 1 + (input_size / SHA256_BLOCK_SIZE);
    
    // Cost = Base * Blocks * Complexity
    // Complexity factor normalized to 1.0 for SHA-256 (64/64)
    return SHA256_BASE_WU * num_blocks * (SHA256_ROUNDS / 64);
}
