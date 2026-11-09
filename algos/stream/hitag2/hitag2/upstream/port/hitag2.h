/* C translation of hitag.py (HITAG2 cipher, "Implemented by Aram Verstegen"), from the repository
 * https://github.com/jackiecan/hitag2 (no license stated). Line-by-line port, see ../ORIGIN.md. */
#ifndef HITAG2_H
#define HITAG2_H
#include <stddef.h>
#include <stdint.h>

/* hitag2_init(key, uid, nonce): key is a 48-bit integer, uid and nonce 32-bit. Returns the 48-bit lfsr state. */
uint64_t hitag2_init(uint64_t key, uint32_t uid, uint32_t nonce);
/* hitag2(state, length): writes `nbits` keystream bits to `out`, first generated bit at the most significant bit
 * of out[0] (C has no big integers: this is the original's returned integer as big-endian bytes, left aligned),
 * and advances *state. out must have room for (nbits + 7) / 8 bytes; unused low bits of the last byte are zero. */
void hitag2_keystream(uint64_t *state, uint8_t *out, size_t nbits);
#endif
