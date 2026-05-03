/* parallelhash.h — ParallelHash-128 and ParallelHash-256 (NIST SP 800-185 §6)
 *
 * Single-threaded reference implementation. Parallelism is not exploited;
 * all blocks are hashed sequentially, which produces identical output to a
 * parallel implementation.
 *
 *   ParallelHash128(X, B, L, S):
 *     n   = max(ceil(|X| / B), 1)
 *     z_i = cSHAKE128(X[i*B..(i+1)*B-1], 256, "", "")  for i in 0..n-1
 *     out = cSHAKE128(left_encode(B) || z_0 || … || z_{n-1}
 *                     || right_encode(n) || right_encode(L),
 *                     L, "ParallelHash", S)
 */
#ifndef NEXTSSL_HASH_PARALLELHASH_H
#define NEXTSSL_HASH_PARALLELHASH_H

#include <stdint.h>
#include <stddef.h>

/* B       : block size in bytes (must be > 0).
 * outlen  : desired output length in bytes.
 * Returns 0 on success, -1 on invalid arguments or allocation failure. */
int parallelhash128(const uint8_t *data, size_t datalen, size_t B,
                    const uint8_t *S, size_t Slen,
                    uint8_t *out, size_t outlen);

int parallelhash256(const uint8_t *data, size_t datalen, size_t B,
                    const uint8_t *S, size_t Slen,
                    uint8_t *out, size_t outlen);

#endif /* NEXTSSL_HASH_PARALLELHASH_H */
