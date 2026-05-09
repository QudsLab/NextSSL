/* kangarootwelve.h — KangarooTwelve (K12) hash function
 *
 * KangarooTwelve is a fast hash / XOF based on KeccakP-1600 with 12 rounds
 * and Sakura tree hashing (chunk size = 8192 bytes).
 *
 * Default digest: 32 bytes (256-bit), squeezed from TurboSHAKE128.
 * Customization string S is supported (pass NULL/0 for empty).
 *
 * References:
 *   RFC 9285  — The KangarooTwelve and TurboSHAKE Algorithm Families
 *   https://keccak.team/kangarootwelve.html
 */
#ifndef KANGAROOTWELVE_H
#define KANGAROOTWELVE_H

#include <stddef.h>
#include <stdint.h>
#include "../_k12/turboshake.h"

#define K12_CHUNK_SIZE 8192  /* B = 8192 bytes per leaf chunk */
#define K12_LEAF_LEN   32    /* inner leaf digest length in bytes */

/* -------------------------------------------------------------------------
 * Streaming context
 *
 * Heap allocations (leaf_buf, node_acc) keep sizeof(K12_CTX) well under
 * HASH_OPS_CTX_MAX (2048 bytes).  destroy_fn / hash_adapter_free() must
 * free these fields.
 *
 * For the hash_ops_t wrapper the context is stack-allocated in
 * HASH_OPS_CTX_MAX; the wrapper calls k12_init() which malloc()s leaf_buf.
 * k12_destroy_fields() must be called from the hash_ops_t final() wrapper
 * to prevent leaking heap memory.
 * -------------------------------------------------------------------------*/
typedef struct {
    TURBOSHAKE_CTX node;        /* outer / final node absorb state           */
    TURBOSHAKE_CTX leaf;        /* current leaf absorb state                 */
    uint8_t       *leaf_buf;    /* heap: 8192-byte leaf buffer               */
    size_t         leaf_pos;    /* bytes written to current leaf             */
    uint64_t       leaf_count;  /* completed leaf count                      */
    uint8_t       *node_acc;    /* heap: grows as leaf hashes are appended   */
    size_t         node_acc_len;
    size_t         out_bytes;   /* desired output length                     */
    int            initialized; /* 1 after k12_init */
} K12_CTX;

/* Initialise context.  outlen = desired output bytes (0 = use 32).
 * custom / clen may be NULL / 0. */
int  k12_init   (K12_CTX *ctx, size_t outlen,
                 const uint8_t *custom, size_t clen);
void k12_update (K12_CTX *ctx, const uint8_t *data, size_t dlen);
void k12_final  (K12_CTX *ctx, uint8_t *out);

/* Free heap fields allocated by k12_init (does NOT free ctx itself). */
void k12_destroy_fields(K12_CTX *ctx);

/* One-shot */
int kangarootwelve(const uint8_t *data,   size_t dlen,
                   const uint8_t *custom, size_t clen,
                   uint8_t *out, size_t outlen);

#endif /* KANGAROOTWELVE_H */
