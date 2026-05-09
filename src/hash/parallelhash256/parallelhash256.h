/* parallelhash256.h — ParallelHash256 canonical algorithm entry
 *
 * Thin wrapper over the parallelhash256() one-shot function from
 * src/hash/parallelhash/parallelhash.h.
 * Default output: 64 bytes.  Default block size B: 64 bytes.
 */
#ifndef PARALLELHASH256_H
#define PARALLELHASH256_H

#include "../parallelhash/parallelhash.h"

#define PARALLELHASH256_DIGEST_LENGTH 64
#define PARALLELHASH256_BLOCK_B       64

#endif /* PARALLELHASH256_H */
