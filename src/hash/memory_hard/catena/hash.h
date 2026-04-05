/*
 * Catena-local hash.h — declares the hash wrapper functions used by catena.
 */
#ifndef CATENA_HASH_H
#define CATENA_HASH_H

#include <stdint.h>
#include "catena.h"

void __Hash1(const uint8_t *input, const uint32_t inputlen,
             uint8_t hash[H_LEN]);

void __Hash2(const uint8_t *i1, const uint8_t i1len,
             const uint8_t *i2, const uint8_t i2len,
             uint8_t hash[H_LEN]);

void __Hash3(const uint8_t *i1, const uint8_t i1len,
             const uint8_t *i2, const uint8_t i2len,
             const uint8_t *i3, const uint8_t i3len,
             uint8_t hash[H_LEN]);

void __Hash4(const uint8_t *i1, const uint8_t i1len,
             const uint8_t *i2, const uint8_t i2len,
             const uint8_t *i3, const uint8_t i3len,
             const uint8_t *i4, const uint8_t i4len,
             uint8_t hash[H_LEN]);

void __Hash5(const uint8_t *i1, const uint8_t i1len,
             const uint8_t *i2, const uint8_t i2len,
             const uint8_t *i3, const uint8_t i3len,
             const uint8_t *i4, const uint8_t i4len,
             const uint8_t *i5, const uint8_t i5len,
             uint8_t hash[H_LEN]);

void __HashFast(int vindex, const uint8_t *i1,
                const uint8_t *i2, uint8_t hash[H_LEN]);

void __ResetState(void);

#endif /* CATENA_HASH_H */
