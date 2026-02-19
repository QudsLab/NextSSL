#ifndef DHCM_MATH_H
#define DHCM_MATH_H

#include <stdint.h>
#include <stddef.h>

// Calculate 2^exponent
double dhcm_pow2(uint32_t exponent);

// Ceiling division (a + b - 1) / b
size_t dhcm_ceil_div(size_t a, size_t b);

// Align size to boundary
size_t dhcm_align(size_t size, size_t alignment);

#endif // DHCM_MATH_H
