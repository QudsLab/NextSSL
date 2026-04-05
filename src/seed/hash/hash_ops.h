/* hash_ops.h — All 41+ Hash Algorithm Vtable Instances for Seed System (Plan 404)
 *
 * Re-exports the hash_ops_t type and all extern vtable pointers for use by
 * the seed system. Actual vtable implementations live in src/hash/interface/.
 *
 * Categories:
 *   Blake      (3): blake2b, blake2s, blake3
 *   Fast       (7): sha224, sha256, sha384, sha512, sha512/224, sha512/256, sm3
 *   Legacy    (12): has160, md2, md4, md5, nt, ripemd128/160/256/320, sha0, sha1, whirlpool
 *   MemHard    (8): argon2, argon2d, argon2i, argon2id, balloon(*), bcrypt, catena, scrypt
 *   Sponge     (5): keccak256, sha3-224/256/384/512
 *   XOF        (2): shake128, shake256
 *   Skein      (3): skein256, skein512, skein1024
 *   Extended   (3): sha512/224, sha512/256, kmac128, kmac256
 *
 * (*) balloon compiled if NEXTSSL_HAS_BALLOON defined
 */
#ifndef SEED_HASH_OPS_H
#define SEED_HASH_OPS_H

/* Pull in hash_ops_t type definition */
#include "../../hash/interface/hash_ops.h"

/* -------------------------------------------------------------------------
 * Blake (3)
 * -------------------------------------------------------------------------*/
extern const hash_ops_t blake2b_ops;
extern const hash_ops_t blake2s_ops;
extern const hash_ops_t blake3_ops;

/* -------------------------------------------------------------------------
 * Fast / SHA-2 (7)
 * -------------------------------------------------------------------------*/
extern const hash_ops_t sha224_ops;
extern const hash_ops_t sha256_ops;
extern const hash_ops_t sha384_ops;
extern const hash_ops_t sha512_ops;
extern const hash_ops_t sha512_224_ops;
extern const hash_ops_t sha512_256_ops;
extern const hash_ops_t sm3_ops;

/* -------------------------------------------------------------------------
 * Legacy / Weak ⚠️ (12)
 * -------------------------------------------------------------------------*/
extern const hash_ops_t has160_ops;
extern const hash_ops_t md2_ops;
extern const hash_ops_t md4_ops;
extern const hash_ops_t md5_ops;
extern const hash_ops_t nt_ops;
extern const hash_ops_t ripemd128_ops;
extern const hash_ops_t ripemd160_ops;
extern const hash_ops_t ripemd256_ops;
extern const hash_ops_t ripemd320_ops;
extern const hash_ops_t sha0_ops;
extern const hash_ops_t sha1_ops;
extern const hash_ops_t whirlpool_ops;

/* -------------------------------------------------------------------------
 * Memory-Hard (8)
 * -------------------------------------------------------------------------*/
extern const hash_ops_t argon2_ops;     /* generic/default Argon2 */
extern const hash_ops_t argon2d_ops;
extern const hash_ops_t argon2i_ops;
extern const hash_ops_t argon2id_ops;
extern const hash_ops_t bcrypt_ops;
extern const hash_ops_t catena_ops;
extern const hash_ops_t scrypt_ops;
extern const hash_ops_t yescrypt_ops;   /* replaces balloon in this build */
#ifdef NEXTSSL_HAS_BALLOON
extern const hash_ops_t balloon_ops;
#endif

/* -------------------------------------------------------------------------
 * Sponge / SHA-3 (5)
 * -------------------------------------------------------------------------*/
extern const hash_ops_t keccak256_ops;
extern const hash_ops_t sha3_224_ops;
extern const hash_ops_t sha3_256_ops;
extern const hash_ops_t sha3_384_ops;
extern const hash_ops_t sha3_512_ops;

/* -------------------------------------------------------------------------
 * XOF — Extendable Output Functions (2)
 * -------------------------------------------------------------------------*/
extern const hash_ops_t shake128_ops;
extern const hash_ops_t shake256_ops;

/* -------------------------------------------------------------------------
 * Skein / Threefish (3)
 * -------------------------------------------------------------------------*/
extern const hash_ops_t skein256_ops;
extern const hash_ops_t skein512_ops;
extern const hash_ops_t skein1024_ops;

/* -------------------------------------------------------------------------
 * NIST SP 800-185 KMAC (2)
 * -------------------------------------------------------------------------*/
extern const hash_ops_t kmac128_ops;
extern const hash_ops_t kmac256_ops;

#endif /* SEED_HASH_OPS_H */
