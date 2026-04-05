#ifndef NEXTSSL_MLKEM512_NTT_H
#define NEXTSSL_MLKEM512_NTT_H
#include "params.h"
#include <stdint.h>

extern const int16_t NEXTSSL_MLKEM512_zetas[128];

void NEXTSSL_MLKEM512_ntt(int16_t r[256]);

void NEXTSSL_MLKEM512_invntt(int16_t r[256]);

void NEXTSSL_MLKEM512_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

#endif
