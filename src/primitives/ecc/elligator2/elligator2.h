#ifndef ELLIGATOR2_H
#define ELLIGATOR2_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void elligator2_map(uint8_t curve[32], const uint8_t hidden[32]);
int elligator2_rev(uint8_t hidden[32], const uint8_t public_key[32], uint8_t tweak);
void elligator2_key_pair(uint8_t hidden[32], uint8_t secret_key[32], uint8_t seed[32]);

#ifdef __cplusplus
}
#endif

#endif
