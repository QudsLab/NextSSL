/* hash_cost.h — DHCM Cost Calculation Plugin API (Plan 40005)
 *
 * Formula-driven, architecture-independent cost model for all 46 algorithms.
 * Three aggregate metrics + five structural properties = eight cost dimensions.
 * No wall-clock time. No empirical benchmarking required.
 *
 * Aggregate metrics (vary with parameters, computed from closed-form formulas):
 *   peak_bytes       — peak simultaneous heap allocation (bytes)
 *   bandwidth_bytes  — total bytes read + written through memory
 *   primitive_calls  — calls to the algorithm's inner primitive
 *
 * Structural properties (fixed by algorithm design or derived from params):
 *   dependency_depth    — minimum sequential steps (critical path)
 *   parallel_limit      — internal lanes per evaluation
 *   access_pattern      — SEQUENTIAL / RANDOM / MIXED
 *   memory_tier         — STACK / L1 / L2 / L3 / DRAM
 *   memory_reread_factor — bandwidth / peak (DRAM traffic ratio, ASIC proxy)
 */
#ifndef HASH_COST_H
#define HASH_COST_H

#include <stdint.h>
#include <stddef.h>

/* -----------------------------------------------------------------------
 * Primitive type IDs — identifies which inner primitive is counted.
 * Indexed by HASH_PRIM_* in hash_cost_calibration.h cycles table.
 * ----------------------------------------------------------------------- */
#define HASH_PRIM_SHA256        0x01  /* SHA-256 compression: 512-bit block  */
#define HASH_PRIM_SHA512        0x02  /* SHA-512 compression: 1024-bit block */
#define HASH_PRIM_BLAKE2B       0x03  /* BLAKE2b compression: 1024-bit block */
#define HASH_PRIM_BLAKE2S       0x04  /* BLAKE2s compression: 512-bit block  */
#define HASH_PRIM_BLAKE3        0x05  /* BLAKE3 compress (8 rounds): 512-bit */
#define HASH_PRIM_KECCAK1600    0x06  /* Keccak-f[1600]: 1600-bit state      */
#define HASH_PRIM_ARGON2G       0x07  /* Argon2 G-function: 1 KiB block      */
#define HASH_PRIM_SALSA20_8     0x08  /* Salsa20/8: 64-byte block            */
#define HASH_PRIM_BLAKMA        0x09  /* Lyra2/BlaMka sponge: 96-byte        */
#define HASH_PRIM_SHA256_COMP   0x0A  /* Balloon: SHA-256 compress (=SHA256) */
#define HASH_PRIM_POMELO_F      0x0B  /* POMELO F-call: one 64-bit word      */
#define HASH_PRIM_BLOWFISH_KS   0x0C  /* bcrypt: one Blowfish key schedule   */
#define HASH_PRIM_MONTGOMERY    0x0D  /* Makwa: one 2048-bit Montgomery sq   */
#define HASH_PRIM_RIPEMD        0x0E  /* RIPEMD-160 compression: 512-bit     */
#define HASH_PRIM_WHIRLPOOL     0x0F  /* Whirlpool compression: 512-bit      */
#define HASH_PRIM_THREEFISH256  0x10  /* Skein-256 / Threefish-256 block     */
#define HASH_PRIM_THREEFISH512  0x11  /* Skein-512 / Threefish-512 block     */
#define HASH_PRIM_THREEFISH1024 0x12  /* Skein-1024 / Threefish-1024 block   */
#define HASH_PRIM_SM3           0x13  /* SM3 compression: 512-bit block      */
#define HASH_PRIM_TIGER         0x14  /* Tiger compression: 512-bit block    */
#define HASH_PRIM_MAX           0x15  /* sentinel — one past the last ID     */

/* Bits processed per primitive call — indexed by HASH_PRIM_* */
extern const uint32_t hash_prim_bits[HASH_PRIM_MAX];

/* -----------------------------------------------------------------------
 * Access pattern — how the algorithm traverses its memory allocation
 * ----------------------------------------------------------------------- */
#define HASH_ACCESS_SEQUENTIAL  0x01  /* all accesses deterministic order; cache-friendly  */
#define HASH_ACCESS_RANDOM      0x02  /* accesses depend on data values; TMTO-resistant    */
#define HASH_ACCESS_MIXED       0x03  /* sequential fill phase + random lookup/wander phase*/

/* -----------------------------------------------------------------------
 * Memory tier — which cache level peak_bytes fits into
 * Thresholds are reference values for a modern x86-64 desktop core.
 * ----------------------------------------------------------------------- */
#define HASH_MEM_TIER_STACK     0x00  /* <=   4 KiB — stack / register-allocated           */
#define HASH_MEM_TIER_L1        0x01  /* <=  64 KiB — fits in L1 data cache                */
#define HASH_MEM_TIER_L2        0x02  /* <= 512 KiB — fits in L2 cache                     */
#define HASH_MEM_TIER_L3        0x03  /* <=  32 MiB — fits in shared L3 cache              */
#define HASH_MEM_TIER_DRAM      0x04  /* >   32 MiB — requires DRAM; latency-bottlenecked  */

/* Helper: derive memory tier from peak_bytes */
static inline uint8_t hash_mem_tier(uint64_t p) {
    if (p <=      4096u) return HASH_MEM_TIER_STACK;
    if (p <=     65536u) return HASH_MEM_TIER_L1;
    if (p <=    524288u) return HASH_MEM_TIER_L2;
    if (p <= 33554432u)  return HASH_MEM_TIER_L3;
    return HASH_MEM_TIER_DRAM;
}

/* -----------------------------------------------------------------------
 * hash_cost_t — result of one cost plugin evaluation (all 8 dimensions)
 * ----------------------------------------------------------------------- */
typedef struct hash_cost_s {
    /* Aggregate metrics — computed from closed-form formulas */
    uint64_t  peak_bytes;           /* peak simultaneous heap allocation (exact bytes)     */
    uint64_t  bandwidth_bytes;      /* total bytes read + written through memory           */
    uint64_t  primitive_calls;      /* calls to the algorithm's inner primitive            */
    uint32_t  primitive_id;         /* HASH_PRIM_* constant identifying the primitive      */

    /* Structural: parallelism model */
    uint64_t  dependency_depth;     /* minimum sequential primitive steps (critical path).
                                     * = primitive_calls for fully sequential algorithms.
                                     * = primitive_calls / parallel_limit for multi-lane.  */
    uint32_t  parallel_limit;       /* internal lanes per evaluation (from lane params).
                                     * argon2: p | scrypt: p | balloon: n_threads
                                     * lyra2: nPARALLEL (compile-time = 2) | else: 1.     */

    /* Structural: memory shape */
    uint8_t   access_pattern;       /* HASH_ACCESS_SEQUENTIAL | _RANDOM | _MIXED          */
    uint8_t   memory_tier;          /* HASH_MEM_TIER_* — derived from peak_bytes          */
    uint8_t   _pad[2];              /* alignment padding                                  */
    uint32_t  memory_reread_factor; /* bandwidth_bytes / peak_bytes.
                                     * Proxy for DRAM energy pressure and ASIC resistance:
                                     *   1  — streaming hash (read input once)
                                     *   N  — scrypt N random V-array lookups
                                     *   3t — Argon2 (3 accesses per block per pass)
                                     * High value + DRAM tier = strong ASIC resistance.   */

    /* Derived: bits processed (informational) */
    uint64_t  bit_ops;              /* primitive_calls x prim_bits; check OVF flag        */

    /* Status flags */
    uint32_t  flags;                /* HASH_COST_* flags below                            */
} hash_cost_t;

/* hash_cost_t.flags bits */
#define HASH_COST_EXACT        (1u << 0)  /* all values are exact (no approximation)      */
#define HASH_COST_APPROX       (1u << 1)  /* bandwidth_bytes is estimated, not exact      */
#define HASH_COST_BIT_OPS_OVF  (1u << 2)  /* bit_ops overflowed uint64 (very large params)*/
#define HASH_COST_ZERO_MEM     (1u << 3)  /* peak_bytes fits in stack — no heap involved  */
#define HASH_COST_MEMORY_HARD  (1u << 4)  /* algorithm is memory-hard (peak > 64 KiB)    */
#define HASH_COST_SEQ_HARD     (1u << 5)  /* sequential-hard: no useful internal parallel */

/* -----------------------------------------------------------------------
 * Parameter structs — one per algorithm family.
 * Pass the correct struct pointer to hash_cost_compute().
 * ----------------------------------------------------------------------- */

/* All fast / streaming hash algorithms */
typedef struct {
    uint64_t input_bytes;           /* byte count of data being hashed */
} hash_cost_params_fast_t;

/* argon2id, argon2i, argon2d, argon2 */
typedef struct {
    uint32_t m_kib;                 /* memory in KiB (default 65536 = 64 MiB) */
    uint32_t t_cost;                /* passes (default 2) */
    uint32_t p;                     /* parallelism / lanes (default 1) */
} hash_cost_params_argon2_t;

/* scrypt */
typedef struct {
    uint64_t N;                     /* cost factor (default 16384) */
    uint32_t r;                     /* block multiplier (default 8) */
    uint32_t p;                     /* parallel lanes (default 1) */
} hash_cost_params_scrypt_t;

/* yescrypt — extends scrypt with extra passes and flags */
typedef struct {
    uint64_t N;
    uint32_t r;
    uint32_t p;
    uint32_t t;                     /* extra passes above the base scrypt cost (0 = none) */
    uint32_t flags;                 /* yescrypt flags (0 = classic scrypt-equivalent mode)*/
} hash_cost_params_yescrypt_t;

/* bcrypt */
typedef struct {
    uint32_t work_factor;           /* log2 of key schedule rounds (default 10) */
} hash_cost_params_bcrypt_t;

/* catena */
typedef struct {
    uint8_t  garlic;                /* log2 of node count (adapter=14, ops=8, source=21) */
    uint8_t  lambda;                /* graph traversal passes (default 2) */
} hash_cost_params_catena_t;

/* lyra2 */
typedef struct {
    uint32_t t_cost;                /* time cost (default 1) */
    uint32_t nrows;                 /* matrix rows (default 8) */
    uint32_t ncols;                 /* matrix columns (default 256) */
} hash_cost_params_lyra2_t;

/* balloon */
typedef struct {
    uint32_t s_cost;                /* space cost in KiB (default 1024) */
    uint32_t t_cost;                /* time passes (default 3) */
    uint32_t n_threads;             /* parallel threads (default 1) */
} hash_cost_params_balloon_t;

/* pomelo */
typedef struct {
    uint32_t m_cost;                /* log2(state_bytes / 8192) — default 14 → 128 MiB */
    uint32_t t_cost;                /* log2 of extra passes — default 1 → 2 total passes */
} hash_cost_params_pomelo_t;

/* makwa */
typedef struct {
    uint32_t work_factor;           /* squarings count (default 4096) */
    /* modulus is fixed at 2048 bits via PHC_PUB2048 at compile time */
} hash_cost_params_makwa_t;

/* -----------------------------------------------------------------------
 * Cost function and plugin descriptor types
 * ----------------------------------------------------------------------- */
typedef void (*hash_cost_fn_t)(const void *params, size_t params_size,
                               hash_cost_t *out);

typedef struct hash_cost_plugin_s {
    const char       *name;         /* must match canonical hyphen-form algorithm name */
    uint32_t          primitive_id; /* HASH_PRIM_* for this algorithm                 */
    size_t            params_size;  /* sizeof the correct params struct                */
    hash_cost_fn_t    compute;      /* fills all 8 dimensions of hash_cost_t from params */
} hash_cost_plugin_t;

/* -----------------------------------------------------------------------
 * Plugin registry API
 * ----------------------------------------------------------------------- */

/* Register all built-in cost plugins and validate the table.
 * Call once at startup before any hash_cost_compute() calls.
 * Returns 0 on success, -1 if the internal table fails validation. */
int hash_cost_registry_init(void);

/* Look up the cost plugin for a named algorithm.
 * Returns NULL if not registered.
 * Thread-safe after hash_cost_registry_init() has returned. */
const hash_cost_plugin_t *hash_cost_lookup(const char *algo_name);

/* Compute cost for a named algorithm given its runtime parameters.
 * Fills *out with all eight cost dimensions.
 * Returns  0 on success.
 * Returns -1 if algo_name not found in the registry.
 * Returns -2 if params or out is NULL. */
int hash_cost_compute(const char *algo_name,
                      const void *params, size_t params_size,
                      hash_cost_t *out);

/* Total number of registered algorithms. */
size_t hash_cost_algo_count(void);

#endif /* HASH_COST_H */
