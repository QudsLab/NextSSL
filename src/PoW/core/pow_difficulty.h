#ifndef POW_DIFFICULTY_H
#define POW_DIFFICULTY_H

#include <stdint.h>
#include <stddef.h>

// Convert difficulty bits to target binary
// e.g. 20 bits -> target with 20 leading zeros
int pow_difficulty_bits_to_target(uint32_t bits, uint8_t* out_target, size_t target_len);

// Check if hash meets target (hash < target)
// Returns 1 if valid, 0 if not
int pow_difficulty_check(const uint8_t* hash, const uint8_t* target, size_t len);

#endif // POW_DIFFICULTY_H
