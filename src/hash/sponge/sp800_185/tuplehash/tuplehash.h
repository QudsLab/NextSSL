/* tuplehash.h — TupleHash-128 and TupleHash-256 (NIST SP 800-185 §5)
 *
 * TupleHash is a hash function for tuples (ordered sequences of byte strings).
 *   TupleHash128(X, L, S) =
 *       cSHAKE128(encode_string(X[0]) || … || encode_string(X[n-1])
 *                 || right_encode(L), L, "TupleHash", S)
 */
#ifndef NEXTSSL_HASH_TUPLEHASH_H
#define NEXTSSL_HASH_TUPLEHASH_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    const uint8_t *data;
    size_t         len;
} tuplehash_entry_t;

/* outlen: desired output length in bytes.
 * Returns 0 on success, -1 on invalid arguments. */
int tuplehash128(const tuplehash_entry_t *entries, size_t n_entries,
                 const uint8_t *S, size_t Slen,
                 uint8_t *out, size_t outlen);

int tuplehash256(const tuplehash_entry_t *entries, size_t n_entries,
                 const uint8_t *S, size_t Slen,
                 uint8_t *out, size_t outlen);

#endif /* NEXTSSL_HASH_TUPLEHASH_H */
