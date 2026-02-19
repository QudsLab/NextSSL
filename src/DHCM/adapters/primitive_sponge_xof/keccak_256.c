#include <stdint.h>
#include <stddef.h>

#define KECCAK_256_BASE_WU 1500
#define KECCAK_256_RATE 136

uint64_t dhcm_keccak_256_wu(size_t input_size) {
    size_t num_absorptions = (input_size + KECCAK_256_RATE - 1) / KECCAK_256_RATE;
    if (num_absorptions == 0) num_absorptions = 1;
    return KECCAK_256_BASE_WU * num_absorptions;
}
