/* sha3_512.h — SHA3-512 */
#ifndef SHA3_512_H
#define SHA3_512_H
#include <stdint.h>
#include <stddef.h>
#include "keccak.h"
void sha3_512_hash(const uint8_t *in, size_t inlen, uint8_t out[64]);
#endif /* SHA3_512_H */
