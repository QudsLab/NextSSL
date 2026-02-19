#include <stdint.h>
#include <stddef.h>

#define SHA3_256_BASE_WU 1500
#define SHA3_256_RATE 136

uint64_t dhcm_sha3_256_wu(size_t input_size) {
    size_t num_absorptions = (input_size + SHA3_256_RATE - 1) / SHA3_256_RATE;
    if (num_absorptions == 0) num_absorptions = 1; // Always at least one permutation
    return SHA3_256_BASE_WU * num_absorptions;
}
