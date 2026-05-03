/* sha512_224.h — SHA-512/224 (FIPS 180-4 §5.3.6.1)
 *
 * SHA-512/224 is SHA-512 with different initial hash values and output
 * truncated to 224 bits (28 bytes).  It reuses SHA512_CTX for context
 * storage and sha512_update for the compression function — only the init
 * and final steps differ.
 */
#ifndef SHA512_224_H
#define SHA512_224_H

#include "sha512.h"

#define SHA512_224_DIGEST_LENGTH 28
#define SHA512_224_BLOCK_SIZE    128

/* SHA-512/224 uses the same context type as SHA-512 */
typedef SHA512_CTX SHA512_224_CTX;

void sha512_224_init  (SHA512_224_CTX *ctx);
/* sha512_update is shared — call it directly for streaming */
void sha512_224_final (uint8_t digest[SHA512_224_DIGEST_LENGTH], SHA512_224_CTX *ctx);
void sha512_224_hash  (const uint8_t *data, size_t len,
                       uint8_t digest[SHA512_224_DIGEST_LENGTH]);

#endif /* SHA512_224_H */
