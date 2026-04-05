/* tiger.h — Tiger hash (192-bit, 64-byte block)
 *
 * Designed by Ross Anderson and Eli Biham (1995).
 * Optimised for 64-bit platforms. 24-byte (192-bit) digest.
 */
#ifndef TIGER_H
#define TIGER_H

#include <stdint.h>
#include <stddef.h>

#define TIGER_DIGEST_LENGTH 24
#define TIGER_BLOCK_SIZE    64

typedef struct {
    uint64_t state[3];
    uint64_t count;                 /* bytes processed */
    uint8_t  buffer[TIGER_BLOCK_SIZE];
} TIGER_CTX;

void tiger_init(TIGER_CTX *ctx);
void tiger_update(TIGER_CTX *ctx, const uint8_t *data, size_t len);
void tiger_final(uint8_t digest[TIGER_DIGEST_LENGTH], TIGER_CTX *ctx);
void tiger_hash(const uint8_t *data, size_t len, uint8_t digest[TIGER_DIGEST_LENGTH]);

#endif /* TIGER_H */
