#include <stdint.h>
#include <stddef.h>

#define NT_BASE_WU 400
#define NT_BLOCK_SIZE 64

uint64_t dhcm_nt_wu(size_t input_size) {
    size_t num_blocks = 1 + (input_size / NT_BLOCK_SIZE);
    return NT_BASE_WU * num_blocks;
}
