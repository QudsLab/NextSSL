#ifndef NEXTSSL_MLKEM1024_AVX2_POLYVEC_H
#define NEXTSSL_MLKEM1024_AVX2_POLYVEC_H
#include "params.h"
#include "poly.h"
#include <stdint.h>

typedef struct {
    poly vec[KYBER_K];
} polyvec;

void NEXTSSL_MLKEM1024_AVX2_polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES + 2], const polyvec *a);
void NEXTSSL_MLKEM1024_AVX2_polyvec_decompress(polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES + 12]);

void NEXTSSL_MLKEM1024_AVX2_polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const polyvec *a);
void NEXTSSL_MLKEM1024_AVX2_polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]);

void NEXTSSL_MLKEM1024_AVX2_polyvec_ntt(polyvec *r);
void NEXTSSL_MLKEM1024_AVX2_polyvec_invntt_tomont(polyvec *r);

void NEXTSSL_MLKEM1024_AVX2_polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b);

void NEXTSSL_MLKEM1024_AVX2_polyvec_reduce(polyvec *r);

void NEXTSSL_MLKEM1024_AVX2_polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);

#endif
