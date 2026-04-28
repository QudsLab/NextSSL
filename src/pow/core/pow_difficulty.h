/* pow_difficulty.h — target encoding and hash-meets-target check */
#ifndef POW_DIFFICULTY_H
#define POW_DIFFICULTY_H

#include <stdint.h>
#include <stddef.h>

/* Encode a difficulty as a big-endian target byte array.
 * 'bits' leading zero bits → out_target[0..bits/8] = 0, then partial byte.
 * Returns 0 on success, -1 on bad args. */
int pow_difficulty_bits_to_target(uint32_t bits,
                                  uint8_t *out_target,
                                  size_t   target_len);

/* Returns 1 if hash < target (both big-endian, same length), 0 otherwise. */
int pow_hash_meets_target(const uint8_t *hash,
                          const uint8_t *target,
                          size_t         len);

#endif /* POW_DIFFICULTY_H */
