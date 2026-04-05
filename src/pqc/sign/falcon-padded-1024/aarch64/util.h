#ifndef UTIL_H
#define UTIL_H

#define poly_small_to_fp NEXTSSL_FALCONPADDED1024_AARCH64_smallints_to_fpr

void NEXTSSL_FALCONPADDED1024_AARCH64_smallints_to_fpr(fpr *r, const int8_t *t, unsigned logn);

#endif
