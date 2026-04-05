#ifndef NEXTSSL_MLDSA44_NTT_H
#define NEXTSSL_MLDSA44_NTT_H
#include "params.h"
#include <stdint.h>

void NEXTSSL_MLDSA44_ntt(int32_t a[N]);

void NEXTSSL_MLDSA44_invntt_tomont(int32_t a[N]);

#endif
