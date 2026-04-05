#ifndef NEXTSSL_MLDSA65_ROUNDING_H
#define NEXTSSL_MLDSA65_ROUNDING_H
#include "params.h"
#include <stdint.h>

int32_t NEXTSSL_MLDSA65_power2round(int32_t *a0, int32_t a);

int32_t NEXTSSL_MLDSA65_decompose(int32_t *a0, int32_t a);

unsigned int NEXTSSL_MLDSA65_make_hint(int32_t a0, int32_t a1);

int32_t NEXTSSL_MLDSA65_use_hint(int32_t a, unsigned int hint);

#endif
