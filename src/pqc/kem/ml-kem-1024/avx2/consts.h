#ifndef NEXTSSL_MLKEM1024_AVX2_CONSTS_H
#define NEXTSSL_MLKEM1024_AVX2_CONSTS_H
#include "align.h"
#include "cdecl.h"


typedef ALIGNED_INT16(640) qdata_t;
extern const qdata_t NEXTSSL_MLKEM1024_AVX2_qdata;

#endif
