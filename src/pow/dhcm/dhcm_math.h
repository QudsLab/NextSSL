/* dhcm_math.h — DHCM shared math helpers */
#ifndef DHCM_MATH_H
#define DHCM_MATH_H

#include <stddef.h>
#include <stdint.h>

/* Returns 2.0^exponent as a double */
double dhcm_pow2(uint32_t exponent);

/* Ceiling division: ceil(a / b) */
size_t dhcm_ceil_div(size_t a, size_t b);

/* Round size up to the next multiple of alignment */
size_t dhcm_align(size_t size, size_t alignment);

#endif /* DHCM_MATH_H */
