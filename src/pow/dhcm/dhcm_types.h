/* dhcm_types.h — Dynamic Hash Cost Model: types and enums
 *
 * Single source of truth for all algorithm identifiers and cost structures.
 * All 41 PoW-eligible algorithms are listed — no feature guards, no splits.
 */
#ifndef DHCM_TYPES_H
#define DHCM_TYPES_H

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Algorithm identifiers
 * Grouped by category, values encode group in high byte.
 * ------------------------------------------------------------------------- */
typedef enum {
    DHCM_ALGO_UNKNOWN = 0,

    /* Fast SHA-2 (0x01xx) */
    DHCM_SHA224      = 0x0100,
    DHCM_SHA256      = 0x0101,
    DHCM_SHA384      = 0x0102,
    DHCM_SHA512      = 0x0103,
    DHCM_SHA512_224  = 0x0104,
    DHCM_SHA512_256  = 0x0105,

    /* BLAKE (0x02xx) */
    DHCM_BLAKE2B     = 0x0200,
    DHCM_BLAKE2S     = 0x0201,
    DHCM_BLAKE3      = 0x0202,

    /* SHA-3 / Keccak / KMAC (0x03xx) */
    DHCM_SHA3_224    = 0x0300,
    DHCM_SHA3_256    = 0x0301,
    DHCM_SHA3_384    = 0x0302,
    DHCM_SHA3_512    = 0x0303,
    DHCM_KECCAK256   = 0x0304,
    DHCM_KMAC128     = 0x0305,
    DHCM_KMAC256     = 0x0306,

    /* Sponge XOF (0x04xx) */
    DHCM_SHAKE128    = 0x0400,
    DHCM_SHAKE256    = 0x0401,

    /* Memory-hard (0x05xx) */
    DHCM_ARGON2ID    = 0x0500,
    DHCM_ARGON2I     = 0x0501,
    DHCM_ARGON2D     = 0x0502,
    DHCM_SCRYPT      = 0x0503,
    DHCM_YESCRYPT    = 0x0504,
    DHCM_CATENA      = 0x0505,
    DHCM_LYRA2       = 0x0506,
    DHCM_BCRYPT      = 0x0507,

    /* Skein (0x06xx) */
    DHCM_SKEIN256    = 0x0600,
    DHCM_SKEIN512    = 0x0601,
    DHCM_SKEIN1024   = 0x0602,

    /* Legacy (0x07xx) */
    DHCM_SHA1        = 0x0700,
    DHCM_SHA0        = 0x0701,
    DHCM_MD5         = 0x0702,
    DHCM_MD4         = 0x0703,
    DHCM_MD2         = 0x0704,
    DHCM_NT          = 0x0705,
    DHCM_RIPEMD128   = 0x0706,
    DHCM_RIPEMD160   = 0x0707,
    DHCM_RIPEMD256   = 0x0708,
    DHCM_RIPEMD320   = 0x0709,
    DHCM_WHIRLPOOL   = 0x070A,
    DHCM_HAS160      = 0x070B,
    DHCM_TIGER       = 0x070C,

    /* National standard (0x08xx) */
    DHCM_SM3         = 0x0800,
} DHCMAlgorithm;

/* -------------------------------------------------------------------------
 * Difficulty model
 * ------------------------------------------------------------------------- */
typedef enum {
    DHCM_DIFFICULTY_NONE = 0,          /* single hash, no search (verify only) */
    DHCM_DIFFICULTY_TARGET_BASED,      /* hash(context||nonce) < target — E[N] = 2^bits */
    DHCM_DIFFICULTY_ITERATION_BASED,   /* cost embedded in algo params (e.g. argon2) */
} DHCMDifficultyModel;

/* -------------------------------------------------------------------------
 * Input parameters for cost calculation
 * ------------------------------------------------------------------------- */
typedef struct {
    DHCMAlgorithm     algorithm;
    DHCMDifficultyModel difficulty_model;

    /* target-based difficulty */
    uint32_t target_leading_zeros;    /* number of leading zero bits required */

    /* memory-hard params (argon2, scrypt, yescrypt, catena, lyra2) */
    uint32_t iterations;              /* time cost */
    uint32_t memory_kb;              /* memory cost in KiB */
    uint32_t parallelism;            /* thread/lane count */

    /* bcrypt */
    uint32_t bcrypt_cost;            /* log2 iteration count, default 10 */

    /* generic */
    size_t   input_size;             /* input data length in bytes */
    size_t   output_size;            /* output digest length in bytes */
} DHCMParams;

/* -------------------------------------------------------------------------
 * Output result
 * ------------------------------------------------------------------------- */
typedef struct {
    uint64_t    work_units_per_eval;       /* WU for one hash call */
    uint64_t    memory_units_per_eval;     /* MU (KB) for one hash call */
    double      expected_trials;           /* E[N] = 2^leading_zeros for target-based */
    uint64_t    total_work_units;          /* work_units_per_eval * expected_trials */
    uint64_t    total_memory_units;        /* memory_units_per_eval (peak, not accumulated) */
    uint64_t    verification_work_units;   /* WU to verify one solution (= work_units_per_eval) */
    const char *algorithm_name;            /* human-readable name */
    const char *cost_model_version;        /* "2.0.0" */
} DHCMResult;

#endif /* DHCM_TYPES_H */
