/* plain_hash_adapter.h — Generic plain hash adapter + per-algorithm constructors
 *
 * All plain hash algorithms (SHA-2, SHA-3, BLAKE, Skein, SHAKE, KMAC, legacy)
 * share one implementation via plain_hash_adapter_create(ops).
 * The per-algorithm constructors are thin wrappers that pass the correct ops.
 *
 * Destroy any adapter returned here with hash_adapter_free().
 */
#ifndef PLAIN_HASH_ADAPTER_H
#define PLAIN_HASH_ADAPTER_H

#include "hash_adapter.h"
#include "../interface/hash_ops.h"

/* -------------------------------------------------------------------------
 * Generic constructor — wraps any hash_ops_t into a hash_adapter_t.
 * Returns NULL on allocation failure.
 * -------------------------------------------------------------------------*/
hash_adapter_t *plain_hash_adapter_create(const hash_ops_t *ops);

/* -------------------------------------------------------------------------
 * Per-algorithm typed constructors — Blake (3)
 * -------------------------------------------------------------------------*/
hash_adapter_t *blake2b_adapter_create(void);
hash_adapter_t *blake2s_adapter_create(void);
hash_adapter_t *blake3_adapter_create(void);

/* -------------------------------------------------------------------------
 * Per-algorithm typed constructors — Fast / SHA-2 (7)
 * -------------------------------------------------------------------------*/
hash_adapter_t *sha224_adapter_create(void);
hash_adapter_t *sha256_adapter_create(void);
hash_adapter_t *sha384_adapter_create(void);
hash_adapter_t *sha512_adapter_create(void);
hash_adapter_t *sha512_224_adapter_create(void);
hash_adapter_t *sha512_256_adapter_create(void);
hash_adapter_t *sm3_adapter_create(void);

/* -------------------------------------------------------------------------
 * Per-algorithm typed constructors — Sponge / SHA-3 (5)
 * -------------------------------------------------------------------------*/
hash_adapter_t *sha3_224_adapter_create(void);
hash_adapter_t *sha3_256_adapter_create(void);
hash_adapter_t *sha3_384_adapter_create(void);
hash_adapter_t *sha3_512_adapter_create(void);
hash_adapter_t *keccak256_adapter_create(void);

/* -------------------------------------------------------------------------
 * Per-algorithm typed constructors — XOF (2)
 * -------------------------------------------------------------------------*/
hash_adapter_t *shake128_adapter_create(void);
hash_adapter_t *shake256_adapter_create(void);

/* -------------------------------------------------------------------------
 * Per-algorithm typed constructors — Skein (3)
 * -------------------------------------------------------------------------*/
hash_adapter_t *skein256_adapter_create(void);
hash_adapter_t *skein512_adapter_create(void);
hash_adapter_t *skein1024_adapter_create(void);

/* -------------------------------------------------------------------------
 * Per-algorithm typed constructors — KMAC (2)
 * -------------------------------------------------------------------------*/
hash_adapter_t *kmac128_adapter_create(void);
hash_adapter_t *kmac256_adapter_create(void);

/* -------------------------------------------------------------------------
 * Per-algorithm typed constructors — Legacy / Weak ⚠️ (12)
 * -------------------------------------------------------------------------*/
hash_adapter_t *has160_adapter_create(void);
hash_adapter_t *md2_adapter_create(void);
hash_adapter_t *md4_adapter_create(void);
hash_adapter_t *md5_adapter_create(void);
hash_adapter_t *nt_adapter_create(void);
hash_adapter_t *ripemd128_adapter_create(void);
hash_adapter_t *ripemd160_adapter_create(void);
hash_adapter_t *ripemd256_adapter_create(void);
hash_adapter_t *ripemd320_adapter_create(void);
hash_adapter_t *sha0_adapter_create(void);
hash_adapter_t *sha1_adapter_create(void);
hash_adapter_t *whirlpool_adapter_create(void);

#endif /* PLAIN_HASH_ADAPTER_H */
