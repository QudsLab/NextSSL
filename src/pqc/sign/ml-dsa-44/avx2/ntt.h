#ifndef NEXTSSL_MLDSA44_AVX2_NTT_H
#define NEXTSSL_MLDSA44_AVX2_NTT_H

#include <immintrin.h>

void NEXTSSL_MLDSA44_AVX2_ntt_avx(__m256i *a, const __m256i *NEXTSSL_MLDSA44_AVX2_qdata);
void NEXTSSL_MLDSA44_AVX2_invntt_avx(__m256i *a, const __m256i *NEXTSSL_MLDSA44_AVX2_qdata);

void NEXTSSL_MLDSA44_AVX2_nttunpack_avx(__m256i *a);

void NEXTSSL_MLDSA44_AVX2_pointwise_avx(__m256i *c, const __m256i *a, const __m256i *b, const __m256i *NEXTSSL_MLDSA44_AVX2_qdata);
void NEXTSSL_MLDSA44_AVX2_pointwise_acc_avx(__m256i *c, const __m256i *a, const __m256i *b, const __m256i *NEXTSSL_MLDSA44_AVX2_qdata);

#endif
