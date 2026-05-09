#ifndef WOLF_CRYPT_CURVE448_DET_H
#define WOLF_CRYPT_CURVE448_DET_H

#include "curve448.h"

#ifdef __cplusplus
    extern "C" {
#endif

/* Deterministic Key Generation */
WOLFSSL_API
int wc_curve448_make_key_deterministic(curve448_key* key, const byte* seed, word32 seedSz);

#ifdef __cplusplus
    }
#endif

#endif
