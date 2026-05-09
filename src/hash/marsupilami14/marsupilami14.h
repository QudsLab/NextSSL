/* marsupilami14.h — MarsupilamiFourteen (M14) hash function
 *
 * MarsupilamiFourteen is the 256-bit security sibling of KangarooTwelve,
 * using KeccakP-1600 with 14 rounds and TurboSHAKE256 (rate=136, cap=512).
 * Tree structure is identical to K12: chunk size = 8192 bytes.
 *
 * Default digest: 64 bytes (512-bit).
 *
 * References:
 *   https://keccak.team/marsupilami.html
 *   RFC 9285 (for the K12/M14 family)
 */
#ifndef MARSUPILAMI14_H
#define MARSUPILAMI14_H

#include <stddef.h>
#include <stdint.h>
#include "../_k12/turboshake.h"

#define M14_CHUNK_SIZE 8192
#define M14_LEAF_LEN   64   /* inner leaf digest length: 64 bytes for 256-bit security */

typedef struct {
    TURBOSHAKE_CTX node;
    TURBOSHAKE_CTX leaf;
    uint8_t       *leaf_buf;
    size_t         leaf_pos;
    uint64_t       leaf_count;
    uint8_t       *node_acc;
    size_t         node_acc_len;
    size_t         out_bytes;
    int            initialized;
} M14_CTX;

int  m14_init   (M14_CTX *ctx, size_t outlen,
                 const uint8_t *custom, size_t clen);
void m14_update (M14_CTX *ctx, const uint8_t *data, size_t dlen);
void m14_final  (M14_CTX *ctx, uint8_t *out);
void m14_destroy_fields(M14_CTX *ctx);

int marsupilami14(const uint8_t *data,   size_t dlen,
                  const uint8_t *custom, size_t clen,
                  uint8_t *out, size_t outlen);

#endif /* MARSUPILAMI14_H */
