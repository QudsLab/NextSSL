#include <stdint.h>
#include <stddef.h>

#define SHA3_512_BASE_WU 1800
#define SHA3_512_RATE 72

uint64_t dhcm_sha3_512_wu(size_t input_size) {
    size_t num_absorptions = (input_size + SHA3_512_RATE - 1) / SHA3_512_RATE;
    if (num_absorptions == 0) num_absorptions = 1;
    return SHA3_512_BASE_WU * num_absorptions;
}
