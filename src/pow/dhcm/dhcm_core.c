/* dhcm_core.c — DHCM cost oracle for all 41 PoW algorithms.
 *
 * WU (Work Units) represent normalised CPU operation counts per hash evaluation.
 * MU (Memory Units) represent peak memory in KiB per hash evaluation.
 * All 41 algorithms are handled unconditionally — no feature guards, no splits.
 *
 * Memory-hard defaults (used when params->memory_kb == 0):
 *   argon2*  : t=2,  m=65536 KiB, p=1
 *   scrypt   : N=16384, r=8, p=1  → ~16 MiB
 *   yescrypt : same as scrypt
 *   catena   : g=21 → 2^21 bytes ≈ 2048 KiB
 *   lyra2    : tcost=2, mcost=256*256 blocks ≈ 65536 KiB
 *   bcrypt   : cost=10
 */
#include "dhcm_core.h"
#include "dhcm_difficulty.h"
#include "dhcm_math.h"
#include <string.h>
#include <stdint.h>

/* ---- WU formulas -------------------------------------------------------
 * Base WU constants are normalised so that SHA-256 at block_count=1 == 1000.
 * All values are approximate for difficulty estimation purposes.
 * ---------------------------------------------------------------------- */

/* Fast SHA-2: sha2_base_wu * ceil(input/block_size) */
#define WU_SHA224_BASE    950
#define WU_SHA256_BASE   1000
#define WU_SHA384_BASE   1800
#define WU_SHA512_BASE   2000
#define WU_SHA512_224_BASE 2000
#define WU_SHA512_256_BASE 2000

#define BLOCK_SHA224   64
#define BLOCK_SHA256   64
#define BLOCK_SHA384  128
#define BLOCK_SHA512  128

/* BLAKE */
#define WU_BLAKE2B_BASE   800
#define WU_BLAKE2S_BASE   500
#define WU_BLAKE3_BASE    400
#define BLOCK_BLAKE2B     128
#define BLOCK_BLAKE2S      64
#define BLOCK_BLAKE3       64

/* SHA-3 / Keccak — rate in bytes drives blocks */
#define WU_SHA3_BASE     1500   /* per Keccak-f[1600] permutation */
#define WU_KMAC_BASE     1500
#define RATE_SHA3_224    144
#define RATE_SHA3_256    136
#define RATE_SHA3_384    104
#define RATE_SHA3_512     72
#define RATE_KECCAK256   136
#define RATE_KMAC128     168
#define RATE_KMAC256     136

/* XOF */
#define WU_SHAKE128_BASE 1200
#define WU_SHAKE256_BASE 1500
#define RATE_SHAKE128    168
#define RATE_SHAKE256    136

/* Skein */
#define WU_SKEIN256_BASE  1200
#define WU_SKEIN512_BASE  1500
#define WU_SKEIN1024_BASE 3000
#define BLOCK_SKEIN256     32
#define BLOCK_SKEIN512     64
#define BLOCK_SKEIN1024   128

/* Legacy */
#define WU_SHA1_BASE      800
#define WU_SHA0_BASE      800
#define WU_MD5_BASE       500
#define WU_MD4_BASE       400
#define WU_MD2_BASE      2000   /* S-box heavy, very slow */
#define WU_NT_BASE        400   /* NT is MD4 */
#define WU_RIPEMD128_BASE 1000
#define WU_RIPEMD160_BASE 1200
#define WU_RIPEMD256_BASE 1300
#define WU_RIPEMD320_BASE 1500
#define WU_WHIRLPOOL_BASE 3000  /* AES-like 10-round Miyaguchi-Preneel */
#define WU_HAS160_BASE    1000
#define WU_TIGER_BASE     1200
#define WU_SM3_BASE       2000
#define BLOCK_SHA1   64
#define BLOCK_SHA0   64
#define BLOCK_MD5    64
#define BLOCK_MD4    64
#define BLOCK_MD2    16   /* 16-byte block, many rounds */
#define BLOCK_NT     64
#define BLOCK_RIPEMD 64
#define BLOCK_WHIRLPOOL 64
#define BLOCK_HAS160 64
#define BLOCK_TIGER  64
#define BLOCK_SM3    64

/* Memory-hard default params */
#define ARGON2_DEFAULT_T   2
#define ARGON2_DEFAULT_M   65536   /* 64 MiB */
#define ARGON2_DEFAULT_P   1
#define ARGON2_BLAKE2B_COST 800   /* WU per 1 KiB block */

#define SCRYPT_DEFAULT_N   16384
#define SCRYPT_DEFAULT_R   8
#define SCRYPT_DEFAULT_P   1
#define SCRYPT_BLOCK_COST  512    /* WU per salsa20 block mix */

#define CATENA_DEFAULT_G   21     /* graph size = 2^21 bytes ~ 2048 KiB */
#define CATENA_HASH_COST   800

#define LYRA2_DEFAULT_T    2
#define LYRA2_DEFAULT_M    65536  /* rows * columns * block */
#define LYRA2_BLOCK_COST   600

#define BCRYPT_DEFAULT_COST 10
#define BCRYPT_BASE_WU     600

/* Helper: WU per block hash, scaled up by block count */
static uint64_t block_wu(uint64_t base, size_t input, size_t block_size) {
    size_t blocks = dhcm_ceil_div(input == 0 ? 64 : input, block_size);
    return base * blocks;
}

/* Helper: Keccak-based — WU scaled by rate */
static uint64_t sponge_wu(uint64_t base, size_t input, size_t rate) {
    size_t blocks = dhcm_ceil_div(input == 0 ? 64 : input, rate);
    return base * blocks;
}

void dhcm_result_init(DHCMResult *r) {
    if (!r) return;
    memset(r, 0, sizeof(*r));
    r->expected_trials    = 1.0;
    r->cost_model_version = "2.0.0";
}

int dhcm_core_calculate(const DHCMParams *params, DHCMResult *result) {
    if (!params || !result) return -1;

    dhcm_result_init(result);
    result->algorithm_name = dhcm_algo_name(params->algorithm);

    uint64_t wu  = 0;
    uint64_t mu  = 0;

    switch (params->algorithm) {

    /* ---- Fast SHA-2 --------------------------------------------------- */
    case DHCM_SHA224:
        wu = block_wu(WU_SHA224_BASE, params->input_size, BLOCK_SHA224);
        mu = 1; break;
    case DHCM_SHA256:
        wu = block_wu(WU_SHA256_BASE, params->input_size, BLOCK_SHA256);
        mu = 1; break;
    case DHCM_SHA384:
        wu = block_wu(WU_SHA384_BASE, params->input_size, BLOCK_SHA384);
        mu = 1; break;
    case DHCM_SHA512:
        wu = block_wu(WU_SHA512_BASE, params->input_size, BLOCK_SHA512);
        mu = 1; break;
    case DHCM_SHA512_224:
        wu = block_wu(WU_SHA512_224_BASE, params->input_size, BLOCK_SHA512);
        mu = 1; break;
    case DHCM_SHA512_256:
        wu = block_wu(WU_SHA512_256_BASE, params->input_size, BLOCK_SHA512);
        mu = 1; break;

    /* ---- BLAKE --------------------------------------------------------- */
    case DHCM_BLAKE2B:
        wu = block_wu(WU_BLAKE2B_BASE, params->input_size, BLOCK_BLAKE2B);
        mu = 1; break;
    case DHCM_BLAKE2S:
        wu = block_wu(WU_BLAKE2S_BASE, params->input_size, BLOCK_BLAKE2S);
        mu = 1; break;
    case DHCM_BLAKE3:
        wu = block_wu(WU_BLAKE3_BASE, params->input_size, BLOCK_BLAKE3);
        mu = 1; break;

    /* ---- SHA-3 / Keccak / KMAC ---------------------------------------- */
    case DHCM_SHA3_224:
        wu = sponge_wu(WU_SHA3_BASE, params->input_size, RATE_SHA3_224);
        mu = 1; break;
    case DHCM_SHA3_256:
        wu = sponge_wu(WU_SHA3_BASE, params->input_size, RATE_SHA3_256);
        mu = 1; break;
    case DHCM_SHA3_384:
        wu = sponge_wu(WU_SHA3_BASE, params->input_size, RATE_SHA3_384);
        mu = 1; break;
    case DHCM_SHA3_512:
        wu = sponge_wu(WU_SHA3_BASE, params->input_size, RATE_SHA3_512);
        mu = 1; break;
    case DHCM_KECCAK256:
        wu = sponge_wu(WU_SHA3_BASE, params->input_size, RATE_KECCAK256);
        mu = 1; break;
    case DHCM_KMAC128:
        wu = sponge_wu(WU_KMAC_BASE, params->input_size, RATE_KMAC128);
        mu = 1; break;
    case DHCM_KMAC256:
        wu = sponge_wu(WU_KMAC_BASE, params->input_size, RATE_KMAC256);
        mu = 1; break;

    /* ---- XOF ---------------------------------------------------------- */
    case DHCM_SHAKE128:
        wu = sponge_wu(WU_SHAKE128_BASE, params->input_size, RATE_SHAKE128);
        mu = 1; break;
    case DHCM_SHAKE256:
        wu = sponge_wu(WU_SHAKE256_BASE, params->input_size, RATE_SHAKE256);
        mu = 1; break;

    /* ---- Memory-hard -------------------------------------------------- */
    case DHCM_ARGON2ID:
    case DHCM_ARGON2I:
    case DHCM_ARGON2D: {
        uint32_t t = params->iterations ? params->iterations : ARGON2_DEFAULT_T;
        uint32_t m = params->memory_kb  ? params->memory_kb  : ARGON2_DEFAULT_M;
        uint32_t p = params->parallelism? params->parallelism: ARGON2_DEFAULT_P;
        wu = (uint64_t)t * m * p * ARGON2_BLAKE2B_COST;
        mu = m;
        break;
    }
    case DHCM_SCRYPT:
    case DHCM_YESCRYPT: {
        /* scrypt: N=16384, r=8, p=1  →  WU ≈ N*r*p*SCRYPT_BLOCK_COST */
        uint32_t N = params->iterations ? params->iterations : SCRYPT_DEFAULT_N;
        uint32_t r = params->parallelism? params->parallelism: SCRYPT_DEFAULT_R;
        uint32_t p = 1;
        wu = (uint64_t)N * r * p * SCRYPT_BLOCK_COST;
        mu = (uint64_t)N * r * 128 / 1024;   /* N*r*128 bytes → KiB */
        break;
    }
    case DHCM_CATENA: {
        uint32_t g  = params->iterations ? params->iterations : CATENA_DEFAULT_G;
        uint64_t sz = (uint64_t)1 << g;      /* 2^g bytes */
        wu = sz / 1024 * CATENA_HASH_COST;   /* cost per KiB of graph */
        mu = sz / 1024;
        break;
    }
    case DHCM_LYRA2: {
        uint32_t t = params->iterations ? params->iterations : LYRA2_DEFAULT_T;
        uint32_t m = params->memory_kb  ? params->memory_kb  : LYRA2_DEFAULT_M;
        wu = (uint64_t)t * m * LYRA2_BLOCK_COST;
        mu = m;
        break;
    }
    case DHCM_BCRYPT: {
        uint32_t cost = params->bcrypt_cost ? params->bcrypt_cost : BCRYPT_DEFAULT_COST;
        wu = ((uint64_t)1 << cost) * BCRYPT_BASE_WU;
        mu = 4;   /* Blowfish key schedule: ~4 KiB */
        break;
    }

    /* ---- Skein -------------------------------------------------------- */
    case DHCM_SKEIN256:
        wu = block_wu(WU_SKEIN256_BASE, params->input_size, BLOCK_SKEIN256);
        mu = 1; break;
    case DHCM_SKEIN512:
        wu = block_wu(WU_SKEIN512_BASE, params->input_size, BLOCK_SKEIN512);
        mu = 1; break;
    case DHCM_SKEIN1024:
        wu = block_wu(WU_SKEIN1024_BASE, params->input_size, BLOCK_SKEIN1024);
        mu = 1; break;

    /* ---- Legacy ------------------------------------------------------- */
    case DHCM_SHA1:
        wu = block_wu(WU_SHA1_BASE, params->input_size, BLOCK_SHA1);
        mu = 1; break;
    case DHCM_SHA0:
        wu = block_wu(WU_SHA0_BASE, params->input_size, BLOCK_SHA0);
        mu = 1; break;
    case DHCM_MD5:
        wu = block_wu(WU_MD5_BASE, params->input_size, BLOCK_MD5);
        mu = 1; break;
    case DHCM_MD4:
        wu = block_wu(WU_MD4_BASE, params->input_size, BLOCK_MD4);
        mu = 1; break;
    case DHCM_MD2:
        /* MD2 has 18 rounds per 16-byte block — costs more than WU_MD2_BASE implies */
        wu = block_wu(WU_MD2_BASE * 18, params->input_size, BLOCK_MD2);
        mu = 1; break;
    case DHCM_NT:
        wu = block_wu(WU_NT_BASE, params->input_size, BLOCK_NT);
        mu = 1; break;
    case DHCM_RIPEMD128:
        wu = block_wu(WU_RIPEMD128_BASE, params->input_size, BLOCK_RIPEMD);
        mu = 1; break;
    case DHCM_RIPEMD160:
        wu = block_wu(WU_RIPEMD160_BASE, params->input_size, BLOCK_RIPEMD);
        mu = 1; break;
    case DHCM_RIPEMD256:
        wu = block_wu(WU_RIPEMD256_BASE, params->input_size, BLOCK_RIPEMD);
        mu = 1; break;
    case DHCM_RIPEMD320:
        wu = block_wu(WU_RIPEMD320_BASE, params->input_size, BLOCK_RIPEMD);
        mu = 1; break;
    case DHCM_WHIRLPOOL:
        wu = block_wu(WU_WHIRLPOOL_BASE, params->input_size, BLOCK_WHIRLPOOL);
        mu = 1; break;
    case DHCM_HAS160:
        wu = block_wu(WU_HAS160_BASE, params->input_size, BLOCK_HAS160);
        mu = 1; break;
    case DHCM_TIGER:
        wu = block_wu(WU_TIGER_BASE, params->input_size, BLOCK_TIGER);
        mu = 1; break;
    case DHCM_SM3:
        wu = block_wu(WU_SM3_BASE, params->input_size, BLOCK_SM3);
        mu = 1; break;

    default:
        return -2;
    }

    result->work_units_per_eval      = wu;
    result->memory_units_per_eval    = mu;
    result->expected_trials          = dhcm_expected_trials(
                                           params->difficulty_model,
                                           params->target_leading_zeros);
    result->total_work_units         = (uint64_t)(wu * result->expected_trials);
    result->total_memory_units       = mu;
    result->verification_work_units  = wu;

    return 0;
}

const char *dhcm_algo_name(DHCMAlgorithm algo) {
    switch (algo) {
    case DHCM_SHA224:      return "sha224";
    case DHCM_SHA256:      return "sha256";
    case DHCM_SHA384:      return "sha384";
    case DHCM_SHA512:      return "sha512";
    case DHCM_SHA512_224:  return "sha512-224";
    case DHCM_SHA512_256:  return "sha512-256";
    case DHCM_BLAKE2B:     return "blake2b";
    case DHCM_BLAKE2S:     return "blake2s";
    case DHCM_BLAKE3:      return "blake3";
    case DHCM_SHA3_224:    return "sha3-224";
    case DHCM_SHA3_256:    return "sha3-256";
    case DHCM_SHA3_384:    return "sha3-384";
    case DHCM_SHA3_512:    return "sha3-512";
    case DHCM_KECCAK256:   return "keccak256";
    case DHCM_KMAC128:     return "kmac128";
    case DHCM_KMAC256:     return "kmac256";
    case DHCM_SHAKE128:    return "shake128";
    case DHCM_SHAKE256:    return "shake256";
    case DHCM_ARGON2ID:    return "argon2id";
    case DHCM_ARGON2I:     return "argon2i";
    case DHCM_ARGON2D:     return "argon2d";
    case DHCM_SCRYPT:      return "scrypt";
    case DHCM_YESCRYPT:    return "yescrypt";
    case DHCM_CATENA:      return "catena";
    case DHCM_LYRA2:       return "lyra2";
    case DHCM_BCRYPT:      return "bcrypt";
    case DHCM_SKEIN256:    return "skein256";
    case DHCM_SKEIN512:    return "skein512";
    case DHCM_SKEIN1024:   return "skein1024";
    case DHCM_SHA1:        return "sha1";
    case DHCM_SHA0:        return "sha0";
    case DHCM_MD5:         return "md5";
    case DHCM_MD4:         return "md4";
    case DHCM_MD2:         return "md2";
    case DHCM_NT:          return "nt";
    case DHCM_RIPEMD128:   return "ripemd128";
    case DHCM_RIPEMD160:   return "ripemd160";
    case DHCM_RIPEMD256:   return "ripemd256";
    case DHCM_RIPEMD320:   return "ripemd320";
    case DHCM_WHIRLPOOL:   return "whirlpool";
    case DHCM_HAS160:      return "has160";
    case DHCM_TIGER:       return "tiger";
    case DHCM_SM3:         return "sm3";
    default:               return NULL;
    }
}

DHCMAlgorithm dhcm_algo_from_name(const char *name)
{
    if (!name) return DHCM_ALGO_UNKNOWN;
    /* Fast SHA-2 */
    if (strcmp(name, "sha224")     == 0) return DHCM_SHA224;
    if (strcmp(name, "sha256")     == 0) return DHCM_SHA256;
    if (strcmp(name, "sha384")     == 0) return DHCM_SHA384;
    if (strcmp(name, "sha512")     == 0) return DHCM_SHA512;
    if (strcmp(name, "sha512-224") == 0) return DHCM_SHA512_224;
    if (strcmp(name, "sha512-256") == 0) return DHCM_SHA512_256;
    /* BLAKE */
    if (strcmp(name, "blake2b")    == 0) return DHCM_BLAKE2B;
    if (strcmp(name, "blake2s")    == 0) return DHCM_BLAKE2S;
    if (strcmp(name, "blake3")     == 0) return DHCM_BLAKE3;
    /* SHA-3 / Keccak / KMAC */
    if (strcmp(name, "sha3-224")   == 0) return DHCM_SHA3_224;
    if (strcmp(name, "sha3-256")   == 0) return DHCM_SHA3_256;
    if (strcmp(name, "sha3-384")   == 0) return DHCM_SHA3_384;
    if (strcmp(name, "sha3-512")   == 0) return DHCM_SHA3_512;
    if (strcmp(name, "keccak256")  == 0) return DHCM_KECCAK256;
    if (strcmp(name, "kmac128")    == 0) return DHCM_KMAC128;
    if (strcmp(name, "kmac256")    == 0) return DHCM_KMAC256;
    /* XOF */
    if (strcmp(name, "shake128")   == 0) return DHCM_SHAKE128;
    if (strcmp(name, "shake256")   == 0) return DHCM_SHAKE256;
    /* Memory-hard */
    if (strcmp(name, "argon2id")   == 0) return DHCM_ARGON2ID;
    if (strcmp(name, "argon2i")    == 0) return DHCM_ARGON2I;
    if (strcmp(name, "argon2d")    == 0) return DHCM_ARGON2D;
    if (strcmp(name, "argon2")     == 0) return DHCM_ARGON2ID; /* generic alias */
    if (strcmp(name, "scrypt")     == 0) return DHCM_SCRYPT;
    if (strcmp(name, "yescrypt")   == 0) return DHCM_YESCRYPT;
    if (strcmp(name, "catena")     == 0) return DHCM_CATENA;
    if (strcmp(name, "lyra2")      == 0) return DHCM_LYRA2;
    if (strcmp(name, "bcrypt")     == 0) return DHCM_BCRYPT;
    /* Skein */
    if (strcmp(name, "skein256")   == 0) return DHCM_SKEIN256;
    if (strcmp(name, "skein512")   == 0) return DHCM_SKEIN512;
    if (strcmp(name, "skein1024")  == 0) return DHCM_SKEIN1024;
    /* Legacy */
    if (strcmp(name, "sha1")       == 0) return DHCM_SHA1;
    if (strcmp(name, "sha0")       == 0) return DHCM_SHA0;
    if (strcmp(name, "md5")        == 0) return DHCM_MD5;
    if (strcmp(name, "md4")        == 0) return DHCM_MD4;
    if (strcmp(name, "md2")        == 0) return DHCM_MD2;
    if (strcmp(name, "nt")         == 0) return DHCM_NT;
    if (strcmp(name, "ripemd128")  == 0) return DHCM_RIPEMD128;
    if (strcmp(name, "ripemd160")  == 0) return DHCM_RIPEMD160;
    if (strcmp(name, "ripemd256")  == 0) return DHCM_RIPEMD256;
    if (strcmp(name, "ripemd320")  == 0) return DHCM_RIPEMD320;
    if (strcmp(name, "whirlpool")  == 0) return DHCM_WHIRLPOOL;
    if (strcmp(name, "has160")     == 0) return DHCM_HAS160;
    if (strcmp(name, "tiger")      == 0) return DHCM_TIGER;
    if (strcmp(name, "sm3")        == 0) return DHCM_SM3;
    return DHCM_ALGO_UNKNOWN;
}

int dhcm_cost_for_name(const char *algo_name, uint32_t difficulty_bits,
                       size_t input_size, DHCMResult *result)
{
    if (!algo_name || !result) return -1;

    DHCMAlgorithm id = dhcm_algo_from_name(algo_name);
    if (id == DHCM_ALGO_UNKNOWN) return -2;

    /* Memory-hard algorithms (group 0x05xx) use iteration-based difficulty */
    DHCMDifficultyModel model =
        ((int)id >= 0x0500 && (int)id <= 0x05FF)
        ? DHCM_DIFFICULTY_ITERATION_BASED
        : DHCM_DIFFICULTY_TARGET_BASED;

    DHCMParams p;
    memset(&p, 0, sizeof(p));
    p.algorithm            = id;
    p.difficulty_model     = model;
    p.target_leading_zeros = difficulty_bits;
    p.input_size           = input_size ? input_size : 64;

    return dhcm_core_calculate(&p, result);
}
