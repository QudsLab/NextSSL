/* parallelhash128.h — ParallelHash128 canonical algorithm entry
 *
 * Thin wrapper over the parallelhash128() one-shot function from
 * src/hash/parallelhash/parallelhash.h.
 * Default output: 32 bytes.  Default block size B: 64 bytes.
 */
#ifndef PARALLELHASH128_H
#define PARALLELHASH128_H

#include "../parallelhash/parallelhash.h"

#define PARALLELHASH128_DIGEST_LENGTH 32
#define PARALLELHASH128_BLOCK_B       64   /* default chunk block size */

#endif /* PARALLELHASH128_H */
