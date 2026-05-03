/* sha512_256.h — SHA-512/256 (FIPS 180-4 §5.3.6.2)
 *
 * SHA-512/256 is SHA-512 with different initial hash values and output
 * truncated to 256 bits (32 bytes).  It reuses SHA512_CTX for context
 * storage and sha512_update for the compression function.
 *
 * Note: SHA-512/256 is NOT the same as SHA-256.  The compression function
 * is SHA-512's 80-round schedule operating on 64-bit words.  It is faster
 * than SHA-256 on 64-bit hardware and provides equivalent 128-bit security.
 */
#ifndef SHA512_256_H
#define SHA512_256_H

#include "sha512.h"

#define SHA512_256_DIGEST_LENGTH 32
#define SHA512_256_BLOCK_SIZE    128

typedef SHA512_CTX SHA512_256_CTX;

void sha512_256_init  (SHA512_256_CTX *ctx);
void sha512_256_final (uint8_t digest[SHA512_256_DIGEST_LENGTH], SHA512_256_CTX *ctx);
void sha512_256_hash  (const uint8_t *data, size_t len,
                       uint8_t digest[SHA512_256_DIGEST_LENGTH]);

#endif /* SHA512_256_H */
