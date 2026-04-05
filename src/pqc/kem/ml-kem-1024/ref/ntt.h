#ifndef NEXTSSL_MLKEM1024_NTT_H
#define NEXTSSL_MLKEM1024_NTT_H
#include "params.h"
#include <stdint.h>

extern const int16_t NEXTSSL_MLKEM1024_zetas[128];

void NEXTSSL_MLKEM1024_ntt(int16_t r[256]);

void NEXTSSL_MLKEM1024_invntt(int16_t r[256]);

void NEXTSSL_MLKEM1024_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

#endif
