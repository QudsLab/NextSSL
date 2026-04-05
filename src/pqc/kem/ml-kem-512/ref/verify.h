#ifndef NEXTSSL_MLKEM512_VERIFY_H
#define NEXTSSL_MLKEM512_VERIFY_H
#include "params.h"
#include <stddef.h>
#include <stdint.h>

int NEXTSSL_MLKEM512_verify(const uint8_t *a, const uint8_t *b, size_t len);

void NEXTSSL_MLKEM512_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);

void NEXTSSL_MLKEM512_cmov_int16(int16_t *r, int16_t v, uint16_t b);

#endif
