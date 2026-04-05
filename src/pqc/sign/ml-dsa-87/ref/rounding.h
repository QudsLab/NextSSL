#ifndef NEXTSSL_MLDSA87_ROUNDING_H
#define NEXTSSL_MLDSA87_ROUNDING_H
#include "params.h"
#include <stdint.h>

int32_t NEXTSSL_MLDSA87_power2round(int32_t *a0, int32_t a);

int32_t NEXTSSL_MLDSA87_decompose(int32_t *a0, int32_t a);

unsigned int NEXTSSL_MLDSA87_make_hint(int32_t a0, int32_t a1);

int32_t NEXTSSL_MLDSA87_use_hint(int32_t a, unsigned int hint);

#endif
