#include "dhcm_math.h"
#include <math.h>

double dhcm_pow2(uint32_t exponent) {
    return pow(2.0, (double)exponent);
}

size_t dhcm_ceil_div(size_t a, size_t b) {
    if (b == 0) return 0;
    return (a + b - 1) / b;
}

size_t dhcm_align(size_t size, size_t alignment) {
    if (alignment == 0) return size;
    size_t remainder = size % alignment;
    if (remainder == 0) return size;
    return size + (alignment - remainder);
}
