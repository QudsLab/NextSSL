#include <stdint.h>
#include <stddef.h>

#define MD2_BASE_WU 1200
#define MD2_BLOCK_SIZE 16

uint64_t dhcm_md2_wu(size_t input_size) {
    size_t num_blocks = 1 + (input_size / MD2_BLOCK_SIZE);
    return MD2_BASE_WU * num_blocks;
}
