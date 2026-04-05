#ifndef NEXTSSL_MLKEM1024_AVX2_NTT_H
#define NEXTSSL_MLKEM1024_AVX2_NTT_H

#include <immintrin.h>
#include <stdint.h>

void NEXTSSL_MLKEM1024_AVX2_ntt_avx(__m256i *r, const __m256i *NEXTSSL_MLKEM1024_AVX2_qdata);
void NEXTSSL_MLKEM1024_AVX2_invntt_avx(__m256i *r, const __m256i *NEXTSSL_MLKEM1024_AVX2_qdata);

void NEXTSSL_MLKEM1024_AVX2_nttpack_avx(__m256i *r, const __m256i *NEXTSSL_MLKEM1024_AVX2_qdata);
void NEXTSSL_MLKEM1024_AVX2_nttunpack_avx(__m256i *r, const __m256i *NEXTSSL_MLKEM1024_AVX2_qdata);

void NEXTSSL_MLKEM1024_AVX2_basemul_avx(__m256i *r,
                                        const __m256i *a,
                                        const __m256i *b,
                                        const __m256i *NEXTSSL_MLKEM1024_AVX2_qdata);

void NEXTSSL_MLKEM1024_AVX2_ntttobytes_avx(uint8_t *r, const __m256i *a, const __m256i *NEXTSSL_MLKEM1024_AVX2_qdata);
void NEXTSSL_MLKEM1024_AVX2_nttfrombytes_avx(__m256i *r, const uint8_t *a, const __m256i *NEXTSSL_MLKEM1024_AVX2_qdata);

#endif
