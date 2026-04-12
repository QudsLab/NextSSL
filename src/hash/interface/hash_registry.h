/* hash_registry.h — Hash algorithm registration and lookup (Plan 202)
 *
 * Usage:
 *   1. Call hash_registry_init() once at startup — registers all built-in hashes.
 *   2. Call hash_lookup("sha256") to obtain a pointer to the algorithm's hash_ops_t.
 *   3. External code may register additional hashes with hash_register().
 */
#ifndef HASH_REGISTRY_H
#define HASH_REGISTRY_H

#include "hash_ops.h"

/* Maximum number of simultaneously registered hash algorithms */
#define HASH_REGISTRY_MAX 64

/* -------------------------------------------------------------------------
 * Registry management
 * -------------------------------------------------------------------------*/

/* hash_registry_init — register all 12 built-in hash algorithms.
 * Safe to call multiple times; subsequent calls are no-ops. */
void hash_registry_init(void);

/* hash_register — add a hash_ops_t to the registry.
 * Returns 0 on success, -1 if ops is NULL or the registry is full. */
int hash_register(const hash_ops_t *ops);

/* hash_lookup — find a registered algorithm by name (case-sensitive).
 * Returns pointer to the algorithm's hash_ops_t, or NULL if not found. */
const hash_ops_t *hash_lookup(const char *name);

/* -------------------------------------------------------------------------
 * Extern declarations for built-in hash_ops_t instances
 * (defined in hash_registry.c)
 * -------------------------------------------------------------------------*/
extern const hash_ops_t sha224_ops;
extern const hash_ops_t sha256_ops;
extern const hash_ops_t sha384_ops;
extern const hash_ops_t sha512_ops;
extern const hash_ops_t blake2b_ops;
extern const hash_ops_t blake2s_ops;
extern const hash_ops_t blake3_ops;
extern const hash_ops_t sha3_224_ops;
extern const hash_ops_t sha3_256_ops;
extern const hash_ops_t sha3_384_ops;
extern const hash_ops_t sha3_512_ops;
extern const hash_ops_t keccak256_ops;

/* XOF */
extern const hash_ops_t shake128_ops;
extern const hash_ops_t shake256_ops;

/* Memory-hard (hash_ops_t accumulator wrappers — CTR seed use only) */
extern const hash_ops_t argon2id_ops;
extern const hash_ops_t argon2i_ops;
extern const hash_ops_t argon2d_ops;
extern const hash_ops_t scrypt_ops;
extern const hash_ops_t yescrypt_ops;
extern const hash_ops_t catena_ops;
extern const hash_ops_t lyra2_ops;
extern const hash_ops_t bcrypt_ops;
extern const hash_ops_t pomelo_ops;
extern const hash_ops_t makwa_ops;

/* Legacy ⚠️ — weak/broken, correctness-tested only */
extern const hash_ops_t sha1_ops;
extern const hash_ops_t sha0_ops;
extern const hash_ops_t md5_ops;
extern const hash_ops_t md4_ops;
extern const hash_ops_t md2_ops;
extern const hash_ops_t nt_ops;      /* NT-HASH: accumulator wrapper, no streaming API */
extern const hash_ops_t ripemd128_ops;
extern const hash_ops_t ripemd160_ops;
extern const hash_ops_t ripemd256_ops;
extern const hash_ops_t ripemd320_ops;
extern const hash_ops_t whirlpool_ops;
extern const hash_ops_t has160_ops;
extern const hash_ops_t tiger_ops;   /* Tiger: 192-bit, Anderson & Biham */

/* Skein (public domain, Doug Whiting; wrapper by Werner Dittmann, MIT) */
extern const hash_ops_t skein256_ops;
extern const hash_ops_t skein512_ops;
extern const hash_ops_t skein1024_ops;

/* Plan 207 Phase C — SHA-512 truncated variants */
extern const hash_ops_t sha512_224_ops;
extern const hash_ops_t sha512_256_ops;

/* Plan 207 Phase D — NIST SP 800-185 KMAC */
extern const hash_ops_t kmac128_ops;
extern const hash_ops_t kmac256_ops;

/* Plan 207 Phase F — National standard hashes (GmSSL, NEXTSSL_HAS_GMSSL) */
extern const hash_ops_t sm3_ops;

/* -------------------------------------------------------------------------
 * Purpose-typed registry accessors (Plan 208)
 *
 * Each accessor calls hash_lookup(name) and verifies the corresponding
 * HASH_USAGE_* flag before returning.  Returns NULL if the algorithm does
 * not support that usage.
 *
 * Preferred over passing raw hash_ops_t* to consumer functions; the check
 * happens once at acquisition rather than silently failing later.
 * -------------------------------------------------------------------------*/
const hash_ops_t *hash_for_hmac  (const char *name);
const hash_ops_t *hash_for_pbkdf2(const char *name);
const hash_ops_t *hash_for_hkdf  (const char *name);
const hash_ops_t *hash_for_pow   (const char *name);
const hash_ops_t *hash_for_seed  (const char *name);

#endif /* HASH_REGISTRY_H */

