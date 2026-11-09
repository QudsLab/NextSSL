/* C translation of src/algo.py of https://github.com/amoallim15/xtwine (commit fa1e0706ef92afc2ef3031c16e16c3b6232cb5b3,
 * MIT). Line-by-line port, see ../ORIGIN.md. TWINE-80 / TWINE-128, 64-bit block, 36 rounds. */
#ifndef TWINE_H
#define TWINE_H
#include <stdint.h>

typedef struct {
    uint8_t rk[37][8]; /* RK_32[r][j], r = 1..36 (index 0 unused) */
} twine_ctx;

/* _key_schedule_80 / _key_schedule_128: the key is the big-endian integer of the key bytes. */
void twine_key_schedule_80(twine_ctx *c, const uint8_t key[10]);
void twine_key_schedule_128(twine_ctx *c, const uint8_t key[16]);
/* _encrypt / _decrypt on one 8-byte block (big-endian integer). */
void twine_encrypt(const twine_ctx *c, const uint8_t in[8], uint8_t out[8]);
void twine_decrypt(const twine_ctx *c, const uint8_t in[8], uint8_t out[8]);
#endif
