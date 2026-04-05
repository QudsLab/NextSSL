#ifndef NEXTSSL_MLKEM1024_AVX2_REDUCE_H
#define NEXTSSL_MLKEM1024_AVX2_REDUCE_H
#include "params.h"
#include <immintrin.h>

void NEXTSSL_MLKEM1024_AVX2_reduce_avx(__m256i *r, const __m256i *NEXTSSL_MLKEM1024_AVX2_qdata);
void NEXTSSL_MLKEM1024_AVX2_tomont_avx(__m256i *r, const __m256i *NEXTSSL_MLKEM1024_AVX2_qdata);

#endif
