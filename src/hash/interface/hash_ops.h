/* hash_ops.h — Hash algorithm vtable (Plan 202)
 *
 * Each hash implementation provides a const hash_ops_t describing:
 *   - algorithm name, digest size, block size
 *   - init / update / final function pointers with uniform void *ctx signature
 *   - DHCM cost parameters (wu_per_eval, mu_per_eval, parallelism)
 *
 * Callers allocate an opaque context of at least HASH_OPS_CTX_MAX bytes on
 * the stack and pass it as void *ctx to the three function pointers.
 * The caller is responsible for wiping ctx after use.
 */
#ifndef HASH_OPS_H
#define HASH_OPS_H

#include <stddef.h>
#include <stdint.h>

/* Maximum hash context size in bytes.
 * Sized for blake3_hasher which is ~1912 bytes on all targets. */
#define HASH_OPS_CTX_MAX  2048

/* Maximum compression block size in bytes.
 * SHA-512 and BLAKE2b use 128-byte blocks — the largest of any built-in. */
#define HASH_OPS_MAX_BLOCK 128

/* -------------------------------------------------------------------------
 * usage_flags — bitmask declaring which operations this hash supports.
 *
 * Each hash_ops_t must set usage_flags != 0 on registration (enforced by
 * hash_register).  Callers should obtain a hash for a specific purpose via
 * hash_for_hmac(), hash_for_pbkdf2(), etc. — these check the flag before
 * returning the pointer.  The consumer functions (hmac_compute, pbkdf2_ex,
 * hkdf_ex) also check the flag as defence-in-depth and return -1 on mismatch.
 * -------------------------------------------------------------------------*/
#define HASH_USAGE_HMAC   (1u << 0)  /* valid RFC 2104 HMAC inner hash          */
#define HASH_USAGE_PBKDF2 (1u << 1)  /* valid PBKDF2-HMAC inner hash (RFC 2898) */
#define HASH_USAGE_HKDF   (1u << 2)  /* valid HKDF inner hash (RFC 5869)        */
#define HASH_USAGE_POW    (1u << 3)  /* valid PoW backend hash                  */
#define HASH_USAGE_SEED   (1u << 4)  /* valid seed accumulator hash             */

/* Convenience composites */
#define HASH_USAGE_ALL_KDF (HASH_USAGE_HMAC | HASH_USAGE_PBKDF2 | HASH_USAGE_HKDF)
#define HASH_USAGE_ALL     (HASH_USAGE_ALL_KDF | HASH_USAGE_POW | HASH_USAGE_SEED)

/* -------------------------------------------------------------------------
 * hash_ops_t — vtable for one hash algorithm
 * -------------------------------------------------------------------------
 * ctx  — caller-allocated opaque buffer, at least HASH_OPS_CTX_MAX bytes.
 * out  — caller-allocated output buffer, at least digest_size bytes.
 */
typedef struct hash_ops_s {
    const char  *name;          /* e.g. "sha256", "blake3", "argon2id" */
    size_t       digest_size;   /* hash output length in bytes */
    size_t       block_size;    /* compression block size in bytes */
    uint32_t     usage_flags;   /* HASH_USAGE_* bitmask — must be non-zero */

    /* Standard streaming interface */
    void       (*init)  (void *ctx);
    void       (*update)(void *ctx, const uint8_t *data, size_t len);
    void       (*final) (void *ctx, uint8_t *out);

    /* DHCM cost parameters — filled by each hash on registration.
     * wu_per_eval  = work units per single hash evaluation (relative cost)
     * mu_per_eval  = memory units per evaluation; non-zero only for Argon2.
     * parallelism  = Argon2 parallelism factor; 1 for all other hashes. */
    double       wu_per_eval;
    double       mu_per_eval;
    uint32_t     parallelism;
} hash_ops_t;

#endif /* HASH_OPS_H */
