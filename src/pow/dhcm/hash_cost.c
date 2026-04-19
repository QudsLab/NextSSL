/* hash_cost.c — DHCM Cost Plugin Registry (Plan 40005)
 *
 * Implements all 46 cost plugins: one compute() per algorithm (or family).
 * Every compute() fills ALL eight cost dimensions in hash_cost_t.
 *
 * Formula sources: ALGO46 documents + source-verified constants:
 *   pomelo.c      state_size = 8192 << m_cost
 *   argon2.c      segment_length alignment enforcement
 *   crypto_scrypt-ref.c  V/B/XY three-part allocation in smix()
 *   catena-BRG.c  GARLIC / H_LEN / lambda
 *   Lyra2.h       BLOCK_LEN_INT64 = 12 → cell = 96 bytes
 *   balloon/constants.h  BLOCK_SIZE=32, N_NEIGHBORS=3
 *   makwa.c       NLIMBS=64 → 2048-bit modulus, fixed PHC_PUB2048
 */
#include "hash_cost.h"
#include <string.h>
#include <stdint.h>

/* -----------------------------------------------------------------------
 * Primitive bits-per-call table (extern declared in hash_cost.h)
 * ----------------------------------------------------------------------- */
const uint32_t hash_prim_bits[HASH_PRIM_MAX] = {
    [HASH_PRIM_SHA256]       =  512,  /* 64-byte input block  */
    [HASH_PRIM_SHA512]       = 1024,  /* 128-byte input block */
    [HASH_PRIM_BLAKE2B]      = 1024,  /* 128-byte input block */
    [HASH_PRIM_BLAKE2S]      =  512,  /* 64-byte input block  */
    [HASH_PRIM_BLAKE3]       =  512,  /* 64-byte input block  */
    [HASH_PRIM_KECCAK1600]   = 1600,  /* full state permuted  */
    [HASH_PRIM_ARGON2G]      = 8192,  /* 1 KiB block          */
    [HASH_PRIM_SALSA20_8]    =  512,  /* 64-byte block        */
    [HASH_PRIM_BLAKMA]       =  768,  /* 96-byte sponge row   */
    [HASH_PRIM_SHA256_COMP]  =  512,  /* same as SHA-256      */
    [HASH_PRIM_POMELO_F]     =   64,  /* one 64-bit word      */
    [HASH_PRIM_BLOWFISH_KS]  =   64,  /* ~530 Encrypt × 64b  */
    [HASH_PRIM_MONTGOMERY]   = 4096,  /* 2048-bit squaring × 2*/
    [HASH_PRIM_RIPEMD]       =  512,  /* 64-byte block        */
    [HASH_PRIM_WHIRLPOOL]    =  512,  /* 64-byte block        */
    [HASH_PRIM_THREEFISH256] =  256,  /* 32-byte block        */
    [HASH_PRIM_THREEFISH512] =  512,  /* 64-byte block        */
    [HASH_PRIM_THREEFISH1024]= 1024,  /* 128-byte block       */
    [HASH_PRIM_SM3]          =  512,  /* 64-byte block        */
    [HASH_PRIM_TIGER]        =  512,  /* 64-byte block        */
};

/* -----------------------------------------------------------------------
 * Internal helpers
 * ----------------------------------------------------------------------- */

/* Ceiling integer division */
static inline uint64_t ceil_div64(uint64_t a, uint64_t b) {
    return (a + b - 1) / b;
}

/* Compute memory_reread_factor safely (avoid divide-by-zero) */
static inline uint32_t reread_factor(uint64_t bandwidth, uint64_t peak) {
    if (peak == 0) return 1;
    uint64_t r = bandwidth / peak;
    return (r > 0xFFFFFFFFu) ? 0xFFFFFFFFu : (uint32_t)r;
}

/* Check if bit_ops would overflow and set flag */
static inline uint64_t safe_bit_ops(uint64_t prim_calls, uint32_t prim_id,
                                    uint32_t *flags_out) {
    if (prim_id == 0 || prim_id >= HASH_PRIM_MAX) return 0;
    uint64_t bits = hash_prim_bits[prim_id];
    /* overflow check: if prim_calls > UINT64_MAX / bits */
    if (bits > 0 && prim_calls > UINT64_MAX / bits) {
        *flags_out |= HASH_COST_BIT_OPS_OVF;
        return UINT64_MAX;
    }
    return prim_calls * bits;
}

/* -----------------------------------------------------------------------
 * Fast / streaming hash cost implementations
 *
 * These families differ only in block size and primitive ID.
 * Structural properties are identical: sequential, stack-allocated, serial.
 * ----------------------------------------------------------------------- */

static void fast_hash_impl(uint64_t input_bytes, uint64_t block_bytes,
                           uint32_t prim_id, hash_cost_t *out)
{
    uint64_t blocks = ceil_div64(input_bytes == 0 ? 64 : input_bytes, block_bytes);

    out->peak_bytes          = 0;
    out->bandwidth_bytes     = input_bytes == 0 ? 64 : input_bytes;
    out->primitive_calls     = blocks;
    out->primitive_id        = prim_id;
    out->dependency_depth    = blocks;      /* fully sequential */
    out->parallel_limit      = 1;
    out->access_pattern      = HASH_ACCESS_SEQUENTIAL;
    out->memory_tier         = HASH_MEM_TIER_STACK;
    out->memory_reread_factor= 1;           /* input read once */
    out->flags               = HASH_COST_EXACT | HASH_COST_ZERO_MEM;
    out->bit_ops             = safe_bit_ops(blocks, prim_id, &out->flags);
}

/* SHA-224 / SHA-256 — 64-byte block */
static void sha256_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    fast_hash_impl(par->input_bytes, 64, HASH_PRIM_SHA256, out);
}

/* SHA-384 / SHA-512 / SHA-512-224 / SHA-512-256 — 128-byte block */
static void sha512_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    fast_hash_impl(par->input_bytes, 128, HASH_PRIM_SHA512, out);
}

/* BLAKE2b — 128-byte block */
static void blake2b_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    fast_hash_impl(par->input_bytes, 128, HASH_PRIM_BLAKE2B, out);
}

/* BLAKE2s — 64-byte block */
static void blake2s_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    fast_hash_impl(par->input_bytes, 64, HASH_PRIM_BLAKE2S, out);
}

/* BLAKE3 — 64-byte chunk (8 rounds) */
static void blake3_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    fast_hash_impl(par->input_bytes, 64, HASH_PRIM_BLAKE3, out);
}

/* -----------------------------------------------------------------------
 * Keccak / SHA-3 family — sponge absorb + fixed squeeze
 * rate = (1600 - capacity) / 8 bytes
 * ----------------------------------------------------------------------- */

static void keccak_cost_impl(uint64_t input_bytes, uint64_t rate_bytes,
                              uint64_t output_bytes, hash_cost_t *out)
{
    uint64_t absorb  = ceil_div64(input_bytes == 0 ? rate_bytes : input_bytes, rate_bytes);
    uint64_t squeeze = ceil_div64(output_bytes == 0 ? rate_bytes : output_bytes, rate_bytes);
    uint64_t total   = absorb + squeeze;

    out->peak_bytes          = 200;           /* 1600-bit state = 200 bytes on stack */
    out->bandwidth_bytes     = input_bytes == 0 ? rate_bytes : input_bytes;
    out->primitive_calls     = total;
    out->primitive_id        = HASH_PRIM_KECCAK1600;
    out->dependency_depth    = total;
    out->parallel_limit      = 1;
    out->access_pattern      = HASH_ACCESS_SEQUENTIAL;
    out->memory_tier         = HASH_MEM_TIER_STACK;
    out->memory_reread_factor= 1;
    out->flags               = HASH_COST_EXACT | HASH_COST_ZERO_MEM;
    out->bit_ops             = safe_bit_ops(total, HASH_PRIM_KECCAK1600, &out->flags);
}

/* SHA3-224: rate=144, output=28 bytes */
static void sha3_224_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    keccak_cost_impl(par->input_bytes, 144, 28, out);
}
/* SHA3-256: rate=136, output=32 bytes */
static void sha3_256_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    keccak_cost_impl(par->input_bytes, 136, 32, out);
}
/* SHA3-384: rate=104, output=48 bytes */
static void sha3_384_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    keccak_cost_impl(par->input_bytes, 104, 48, out);
}
/* SHA3-512: rate=72, output=64 bytes */
static void sha3_512_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    keccak_cost_impl(par->input_bytes, 72, 64, out);
}
/* Keccak-256 (bare, rate=136, output=32) */
static void keccak256_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    keccak_cost_impl(par->input_bytes, 136, 32, out);
}
/* SHAKE-128: rate=168, PoW output=32 bytes */
static void shake128_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    keccak_cost_impl(par->input_bytes, 168, 32, out);
}
/* SHAKE-256: rate=136, PoW output=64 bytes */
static void shake256_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    keccak_cost_impl(par->input_bytes, 136, 64, out);
}
/* KMAC-128: rate=168, absorbs key+input, squeezes at least 32 bytes */
static void kmac128_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    keccak_cost_impl(par->input_bytes, 168, 32, out);
}
/* KMAC-256: rate=136 */
static void kmac256_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    keccak_cost_impl(par->input_bytes, 136, 32, out);
}

/* -----------------------------------------------------------------------
 * Skein — Threefish block variants
 * ----------------------------------------------------------------------- */

/* Skein-256: 32-byte block */
static void skein256_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    fast_hash_impl(par->input_bytes, 32, HASH_PRIM_THREEFISH256, out);
}
/* Skein-512: 64-byte block */
static void skein512_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    fast_hash_impl(par->input_bytes, 64, HASH_PRIM_THREEFISH512, out);
}
/* Skein-1024: 128-byte block */
static void skein1024_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    fast_hash_impl(par->input_bytes, 128, HASH_PRIM_THREEFISH1024, out);
}

/* -----------------------------------------------------------------------
 * Legacy and national-standard fast hashes
 * All use sha256_cost / sha512_cost style with their own primitives.
 * ----------------------------------------------------------------------- */

/* RIPEMD-128/160/256/320: 64-byte block, RIPEMD primitive */
static void ripemd_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    fast_hash_impl(par->input_bytes, 64, HASH_PRIM_RIPEMD, out);
}

/* Whirlpool: 64-byte block, WHIRLPOOL primitive */
static void whirlpool_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    fast_hash_impl(par->input_bytes, 64, HASH_PRIM_WHIRLPOOL, out);
}

/* Tiger: 64-byte block, TIGER primitive */
static void tiger_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    fast_hash_impl(par->input_bytes, 64, HASH_PRIM_TIGER, out);
}

/* SM3: 64-byte block, SM3 primitive */
static void sm3_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    fast_hash_impl(par->input_bytes, 64, HASH_PRIM_SM3, out);
}

/* SHA-1, SHA-0, MD5, MD4, MD2, NT, HAS-160 all map to SHA256 primitive family
 * (similar 64-byte Merkle-Damgård structure, comparable compression complexity).
 * MD2 is heavier (18 S-box rounds per 16-byte block) — modelled separately. */
static void sha1_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    fast_hash_impl(par->input_bytes, 64, HASH_PRIM_SHA256, out);
}
static void md5_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    fast_hash_impl(par->input_bytes, 64, HASH_PRIM_SHA256, out);
}
static void md4_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    fast_hash_impl(par->input_bytes, 64, HASH_PRIM_SHA256, out);
}
/* MD2: 16-byte block, S-box heavy — multiply primitive_calls by 18 rounds */
static void md2_cost(const void *p, size_t sz, hash_cost_t *out) {
    const hash_cost_params_fast_t *par = p;
    uint64_t input   = par->input_bytes == 0 ? 16 : par->input_bytes;
    uint64_t blocks  = ceil_div64(input, 16);
    uint64_t rounds  = blocks * 18;  /* MD2 processes each block in 18 S-box rounds */

    out->peak_bytes          = 0;
    out->bandwidth_bytes     = input;
    out->primitive_calls     = rounds;
    out->primitive_id        = HASH_PRIM_SHA256;   /* closest in character */
    out->dependency_depth    = rounds;
    out->parallel_limit      = 1;
    out->access_pattern      = HASH_ACCESS_SEQUENTIAL;
    out->memory_tier         = HASH_MEM_TIER_STACK;
    out->memory_reread_factor= 1;
    out->flags               = HASH_COST_EXACT | HASH_COST_ZERO_MEM;
    out->bit_ops             = safe_bit_ops(rounds, HASH_PRIM_SHA256, &out->flags);
}

/* -----------------------------------------------------------------------
 * Memory-hard cost implementations
 * ----------------------------------------------------------------------- */

/* ---- Argon2 (id, i, d, bare alias) -----------------------------------
 * Source: argon2.c segment_length formula + pass structure.
 * peak_bytes    = m_prime × 1024 (m_prime aligned to 4×p blocks)
 * bandwidth     = peak × t_cost × 3  (1 write + 2 reads per G call per pass)
 * primitive_calls = m_prime × t_cost  (one G call per block per pass)
 * dependency_depth = primitive_calls / p  (lanes run in parallel)
 * ----------------------------------------------------------------------- */
static void argon2_cost(const void *p, size_t sz, hash_cost_t *out)
{
    const hash_cost_params_argon2_t *par = p;

    uint32_t t = par->t_cost     ? par->t_cost     : 2;
    uint32_t m = par->m_kib      ? par->m_kib      : 65536;
    uint32_t lanes = par->p      ? par->p           : 1;

    /* Minimum enforcement: m must be >= 8 * p */
    if (m < 8u * lanes) m = 8u * lanes;

    /* Alignment: floor to (4×p) multiple of blocks */
    uint32_t seg    = m / (lanes * 4);
    uint32_t m_prime = seg * (lanes * 4);   /* actual block count */

    uint64_t peak   = (uint64_t)m_prime * 1024;
    uint64_t prims  = (uint64_t)m_prime * t;
    uint64_t bw     = peak * (uint64_t)t * 3;  /* 3 accesses per block per pass */

    out->peak_bytes          = peak;
    out->bandwidth_bytes     = bw;
    out->primitive_calls     = prims;
    out->primitive_id        = HASH_PRIM_ARGON2G;
    out->dependency_depth    = prims / lanes;
    out->parallel_limit      = lanes;
    out->access_pattern      = HASH_ACCESS_MIXED;
    out->memory_tier         = hash_mem_tier(peak);
    out->memory_reread_factor= reread_factor(bw, peak);
    out->flags               = HASH_COST_EXACT | HASH_COST_MEMORY_HARD;
    out->bit_ops             = safe_bit_ops(prims, HASH_PRIM_ARGON2G, &out->flags);
}

/* argon2i uses sequential block generation: access_pattern = SEQUENTIAL */
static void argon2i_cost(const void *p, size_t sz, hash_cost_t *out)
{
    argon2_cost(p, sz, out);
    out->access_pattern = HASH_ACCESS_SEQUENTIAL;
}

/* ---- scrypt ----------------------------------------------------------
 * Source: crypto_scrypt-ref.c smix() — V/B/XY three-part allocation.
 * V   = 128 × r × N  (per-lane lookup table, filled sequentially)
 * B   = 128 × r × p  (input/output block, one per lane)
 * XY  = 256 × r      (working scratch per lane; p lanes share one XY)
 * peak = V + B + XY  (worst case: p lanes fully resident)
 *
 * Bandwidth:
 *   fill phase  : write N×128r bytes to V (sequential)
 *   lookup phase: N random reads of 128r bytes from V
 *   mix writes  : N×128r bytes written to X each step
 *   per lane ≈ N×128r × 3; total × p
 *   plus B read once in + written once out
 * ----------------------------------------------------------------------- */
static void scrypt_cost(const void *p, size_t sz, hash_cost_t *out)
{
    const hash_cost_params_scrypt_t *par = p;

    uint64_t N    = par->N ? par->N : 16384;
    uint32_t r    = par->r ? par->r : 8;
    uint32_t lanes= par->p ? par->p : 1;

    uint64_t V    = (uint64_t)128 * r * N;
    uint64_t B    = (uint64_t)128 * r * lanes;
    uint64_t XY   = (uint64_t)256 * r;
    uint64_t peak = V + B + XY;

    /* 2 BlockMix per N ROMix step; each BlockMix calls 2r Salsa20/8 */
    uint64_t prims = (uint64_t)4 * N * r * lanes;

    uint64_t bw = (uint64_t)128 * r * N * 3 * lanes + B * 2;

    out->peak_bytes          = peak;
    out->bandwidth_bytes     = bw;
    out->primitive_calls     = prims;
    out->primitive_id        = HASH_PRIM_SALSA20_8;
    /* dependency_depth: 2N BlockMix calls per lane (serial within lane) */
    out->dependency_depth    = (uint64_t)2 * N;
    out->parallel_limit      = lanes;
    out->access_pattern      = HASH_ACCESS_MIXED;
    out->memory_tier         = hash_mem_tier(peak);
    out->memory_reread_factor= reread_factor(bw, peak);
    out->flags               = HASH_COST_EXACT | HASH_COST_MEMORY_HARD;
    out->bit_ops             = safe_bit_ops(prims, HASH_PRIM_SALSA20_8, &out->flags);
}

/* ---- yescrypt (classic mode and extended) ----------------------------
 * Classic mode (flags=0, t=0): identical to scrypt.
 * Extended mode (t>0): t extra ROM passes; total passes = 1 + t.
 *
 * The implementation contains OpenMP and scalar paths. This model tracks the
 * configured lane count `p`, but callers should expect scalar execution when
 * the library is built without OpenMP support.
 * ----------------------------------------------------------------------- */
static void yescrypt_cost(const void *p, size_t sz, hash_cost_t *out)
{
    const hash_cost_params_yescrypt_t *par = p;

    /* Base: treat as scrypt */
    hash_cost_params_scrypt_t sp = { par->N, par->r, par->p };
    scrypt_cost(&sp, sizeof sp, out);

    if (par->t > 0) {
        out->primitive_calls += out->primitive_calls * par->t;
        out->bandwidth_bytes += out->bandwidth_bytes * par->t;
        out->dependency_depth = out->primitive_calls / (par->p ? par->p : 1);
        out->bit_ops = safe_bit_ops(out->primitive_calls,
                                    HASH_PRIM_SALSA20_8, &out->flags);
    }
}

/* ---- bcrypt ----------------------------------------------------------
 * Fixed Blowfish state: 18×4 + 4×256×4 = 4168 bytes.
 * Each key schedule reads and rewrites P-array + 4 S-boxes ≈ 2× state.
 * ----------------------------------------------------------------------- */
static void bcrypt_cost(const void *p, size_t sz, hash_cost_t *out)
{
    const hash_cost_params_bcrypt_t *par = p;

    uint32_t wf   = par->work_factor ? par->work_factor : 10;
    uint64_t peak = 4168;                   /* Blowfish state in bytes */
    uint64_t prims= (uint64_t)1u << wf;
    uint64_t bw   = prims * peak * 2;       /* read + write state per schedule */

    out->peak_bytes          = peak;
    out->bandwidth_bytes     = bw;
    out->primitive_calls     = prims;
    out->primitive_id        = HASH_PRIM_BLOWFISH_KS;
    out->dependency_depth    = prims;        /* fully sequential */
    out->parallel_limit      = 1;
    out->access_pattern      = HASH_ACCESS_SEQUENTIAL;
    out->memory_tier         = HASH_MEM_TIER_L1;  /* 4 KiB state fits in L1 */
    out->memory_reread_factor= reread_factor(bw, peak);
    out->flags               = HASH_COST_APPROX | HASH_COST_SEQ_HARD;
    /* bandwidth is approximate: exact depends on password length */
    out->bit_ops             = safe_bit_ops(prims * 530, HASH_PRIM_BLOWFISH_KS,
                                            &out->flags);
    /* ~530 Blowfish Encrypt calls per key schedule × 64 bits each */
    out->bit_ops             = prims * 530 * 64;
}

/* ---- Catena-BRG -------------------------------------------------------
 * Source: catena-BRG.c Flap(): malloc(c × H_LEN), lambda BRG passes.
 * c       = 2^garlic  (node count)
 * H_LEN   = 64        (BLAKE2b output bytes)
 * peak    = c × 64
 * Each pass: c BLAKE2b calls (one per node); plus gamma() ≈ c calls.
 * Total   ≈ (lambda + 1) × c BLAKE2b calls.
 * ----------------------------------------------------------------------- */
static void catena_cost(const void *p, size_t sz, hash_cost_t *out)
{
    const hash_cost_params_catena_t *par = p;

    uint8_t  g      = par->garlic  ? par->garlic  : 21;
    uint8_t  lambda = par->lambda  ? par->lambda  : 2;
    uint64_t c      = (uint64_t)1 << g;
    uint64_t H_LEN  = 64;

    uint64_t peak   = c * H_LEN;
    uint64_t prims  = c * ((uint64_t)lambda + 1);
    uint64_t bw     = peak * ((uint64_t)lambda + 1) * 2;  /* read+write per pass */

    out->peak_bytes          = peak;
    out->bandwidth_bytes     = bw;
    out->primitive_calls     = prims;
    out->primitive_id        = HASH_PRIM_BLAKE2B;
    out->dependency_depth    = prims;   /* graph dependencies: fully serial within BRG */
    out->parallel_limit      = 1;
    out->access_pattern      = HASH_ACCESS_MIXED;
    out->memory_tier         = hash_mem_tier(peak);
    out->memory_reread_factor= reread_factor(bw, peak);
    out->flags               = HASH_COST_APPROX | HASH_COST_MEMORY_HARD;
    out->bit_ops             = safe_bit_ops(prims, HASH_PRIM_BLAKE2B, &out->flags);
}

/* ---- Lyra2 ------------------------------------------------------------
 * Source: Lyra2.h BLOCK_LEN_INT64=12 → cell_bytes=12×8=96.
 *
 * Setup phase  : nrows × ncols sponge absorb calls (fills matrix)
 * Wandering    : t_cost × nrows steps; each step duplex-absorbs 2~rows of ncols cells
 * Total sponge calls ≈ nrows×ncols + t_cost×nrows×ncols×2
 *
 * OpenMP builds keep the original two-lane model. Non-OpenMP builds use the
 * scalar fallback and must report parallel_limit = 1.
 * ----------------------------------------------------------------------- */
static void lyra2_cost(const void *p, size_t sz, hash_cost_t *out)
{
    const hash_cost_params_lyra2_t *par = p;

    uint32_t t_cost = par->t_cost ? par->t_cost : 1;
    uint32_t nrows  = par->nrows  ? par->nrows  : 8;
    uint32_t ncols  = par->ncols  ? par->ncols  : 256;

    uint64_t cell_bytes  = 96;
    uint64_t peak        = (uint64_t)nrows * ncols * cell_bytes;

    uint64_t setup_calls  = (uint64_t)nrows * ncols;
    uint64_t wander_calls = (uint64_t)t_cost * nrows * ncols * 2;
    uint64_t prims        = setup_calls + wander_calls;

    /* Each sponge call reads + writes one 96-byte cell */
    uint64_t bw = prims * cell_bytes * 2;

    out->peak_bytes          = peak;
    out->bandwidth_bytes     = bw;
    out->primitive_calls     = prims;
    out->primitive_id        = HASH_PRIM_BLAKMA;
#ifdef _OPENMP
    out->dependency_depth    = prims / 2;
    out->parallel_limit      = 2;
#else
    out->dependency_depth    = prims;
    out->parallel_limit      = 1;
#endif
    out->access_pattern      = HASH_ACCESS_RANDOM;
    out->memory_tier         = hash_mem_tier(peak);
    out->memory_reread_factor= reread_factor(bw, peak);
    out->flags               = HASH_COST_APPROX | HASH_COST_MEMORY_HARD;
    /* APPROX: wandering row choices are data-dependent; factor×2 is expected-case */
    out->bit_ops             = safe_bit_ops(prims, HASH_PRIM_BLAKMA, &out->flags);
}

/* ---- Balloon ----------------------------------------------------------
 * Source: balloon/constants.h BLOCK_SIZE=32, N_NEIGHBORS=3.
 *         balloon/hash_state.c n_blocks = ceil(s_cost×1024/32), rounded up to even.
 *
 * Expand: n_blocks SHA-256 compressions (one per block)
 * Mix per pass: n_blocks × (1 + delta) SHA-256 compressions
 * Total: n_blocks × (1 + t_cost × (1 + delta)) × n_threads
 * ----------------------------------------------------------------------- */
static void balloon_cost(const void *p, size_t sz, hash_cost_t *out)
{
    const hash_cost_params_balloon_t *par = p;

    uint32_t s_cost   = par->s_cost   ? par->s_cost   : 1024;
    uint32_t t_cost   = par->t_cost   ? par->t_cost   : 3;
    uint32_t n_threads= par->n_threads? par->n_threads : 1;
    uint32_t delta    = 3;    /* N_NEIGHBORS — hardcoded in constants.h */

    uint64_t n_blocks = ((uint64_t)s_cost * 1024 + 31) / 32;
    if (n_blocks & 1) n_blocks++;   /* must be even */

    uint64_t peak   = n_blocks * 32 * n_threads;
    uint64_t prims  = n_blocks * (1 + (uint64_t)t_cost * (1 + delta)) * n_threads;

    /* Expand: write n_blocks×32; Mix: n_blocks written + n_blocks×delta read per pass */
    uint64_t bw = (n_blocks * 32 +
                   (uint64_t)t_cost * n_blocks * 32 +
                   (uint64_t)t_cost * n_blocks * delta * 32) * n_threads;

    out->peak_bytes          = peak;
    out->bandwidth_bytes     = bw;
    out->primitive_calls     = prims;
    out->primitive_id        = HASH_PRIM_SHA256_COMP;
    out->dependency_depth    = prims / n_threads;
    out->parallel_limit      = n_threads;
    out->access_pattern      = HASH_ACCESS_MIXED;
    out->memory_tier         = hash_mem_tier(peak);
    out->memory_reread_factor= reread_factor(bw, peak);
    out->flags               = HASH_COST_EXACT | HASH_COST_MEMORY_HARD;
    out->bit_ops             = safe_bit_ops(prims, HASH_PRIM_SHA256_COMP, &out->flags);
}

/* ---- POMELO -----------------------------------------------------------
 * Source: pomelo.c — state_size = 8192 << m_cost
 *
 * Five phases (source-verified):
 *   Steps 3, 5, 7 : 3 fixed passes over word_count F-calls
 *   Steps 4, 6    : 2 × (1 << t_cost) passes over word_count F+G/H-calls
 *   Total F-calls ≈ (3 + 2 × 2^t_cost) × word_count
 *
 * Each F-call reads 4 words (i-1, i-3, i-17, i-41) + writes 1 → ~5×8=40 bytes.
 * ----------------------------------------------------------------------- */
static void pomelo_cost(const void *p, size_t sz, hash_cost_t *out)
{
    const hash_cost_params_pomelo_t *par = p;

    uint32_t m_cost = par->m_cost;          /* default 14 → 128 MiB */
    uint32_t t_cost = par->t_cost;          /* default 1  → 2 passes */

    uint64_t state_bytes = (uint64_t)8192 << m_cost;
    uint64_t word_count  = state_bytes / 8;  /* uint64_t elements */

    uint64_t var_passes = (uint64_t)2 << t_cost;   /* 2 × 2^t_cost */
    uint64_t prims      = (3 + var_passes) * word_count;

    /* ~40 bytes accessed per F-call (4 reads + 1 write of 8-byte words) */
    uint64_t bw = prims * 40;

    out->peak_bytes          = state_bytes;
    out->bandwidth_bytes     = bw;
    out->primitive_calls     = prims;
    out->primitive_id        = HASH_PRIM_POMELO_F;
    out->dependency_depth    = prims;        /* data-dependent chain → fully serial */
    out->parallel_limit      = 1;
    out->access_pattern      = HASH_ACCESS_MIXED;
    out->memory_tier         = hash_mem_tier(state_bytes);
    out->memory_reread_factor= reread_factor(bw, state_bytes);
    out->flags               = HASH_COST_APPROX | HASH_COST_MEMORY_HARD;
    out->bit_ops             = safe_bit_ops(prims, HASH_PRIM_POMELO_F, &out->flags);
}

/* ---- Makwa -----------------------------------------------------------
 * Source: makwa.c NLIMBS=64, fixed 2048-bit modulus (PHC_PUB2048).
 * Working state ≈ 6 × 256 bytes = 1536 bytes (all in L1/stack).
 * One Montgomery squaring: 64×64 = 4096 multiply-add pairs (schoolbook).
 * ----------------------------------------------------------------------- */
static void makwa_cost(const void *p, size_t sz, hash_cost_t *out)
{
    const hash_cost_params_makwa_t *par = p;

    uint32_t wf   = par->work_factor ? par->work_factor : 4096;
    uint64_t peak = 1536;    /* ~6 limb arrays of 256 bytes */
    uint64_t prims= wf;

    /* Each squaring: read 256 (x) + 256 (n) + write 256 → 768 bytes */
    uint64_t bw = (uint64_t)wf * 768;

    out->peak_bytes          = peak;
    out->bandwidth_bytes     = bw;
    out->primitive_calls     = prims;
    out->primitive_id        = HASH_PRIM_MONTGOMERY;
    out->dependency_depth    = prims;    /* each squaring depends on previous output */
    out->parallel_limit      = 1;
    out->access_pattern      = HASH_ACCESS_SEQUENTIAL;
    out->memory_tier         = HASH_MEM_TIER_L1;   /* 1.5 KiB fits in L1 */
    out->memory_reread_factor= reread_factor(bw, peak);
    out->flags               = HASH_COST_EXACT | HASH_COST_SEQ_HARD;
    /* bit_ops: 2048-bit modulus × 2 per squaring */
    out->bit_ops             = (uint64_t)wf * 2048 * 2;
}

/* -----------------------------------------------------------------------
 * Plugin table — one entry per registered algorithm name.
 * Names must match the canonical hyphen-form used in hash_ops_t.name.
 * ----------------------------------------------------------------------- */
static const hash_cost_plugin_t s_plugins[] = {
    /* ---- Fast SHA-2 -------------------------------------------------- */
    { "sha224",      HASH_PRIM_SHA256,        sizeof(hash_cost_params_fast_t), sha256_cost  },
    { "sha256",      HASH_PRIM_SHA256,        sizeof(hash_cost_params_fast_t), sha256_cost  },
    { "sha384",      HASH_PRIM_SHA512,        sizeof(hash_cost_params_fast_t), sha512_cost  },
    { "sha512",      HASH_PRIM_SHA512,        sizeof(hash_cost_params_fast_t), sha512_cost  },
    { "sha512-224",  HASH_PRIM_SHA512,        sizeof(hash_cost_params_fast_t), sha512_cost  },
    { "sha512-256",  HASH_PRIM_SHA512,        sizeof(hash_cost_params_fast_t), sha512_cost  },
    /* ---- BLAKE ------------------------------------------------------- */
    { "blake2b",     HASH_PRIM_BLAKE2B,       sizeof(hash_cost_params_fast_t), blake2b_cost },
    { "blake2s",     HASH_PRIM_BLAKE2S,       sizeof(hash_cost_params_fast_t), blake2s_cost },
    { "blake3",      HASH_PRIM_BLAKE3,        sizeof(hash_cost_params_fast_t), blake3_cost  },
    /* ---- SHA-3 / Keccak / KMAC --------------------------------------- */
    { "sha3-224",    HASH_PRIM_KECCAK1600,    sizeof(hash_cost_params_fast_t), sha3_224_cost},
    { "sha3-256",    HASH_PRIM_KECCAK1600,    sizeof(hash_cost_params_fast_t), sha3_256_cost},
    { "sha3-384",    HASH_PRIM_KECCAK1600,    sizeof(hash_cost_params_fast_t), sha3_384_cost},
    { "sha3-512",    HASH_PRIM_KECCAK1600,    sizeof(hash_cost_params_fast_t), sha3_512_cost},
    { "keccak256",   HASH_PRIM_KECCAK1600,    sizeof(hash_cost_params_fast_t), keccak256_cost},
    { "shake128",    HASH_PRIM_KECCAK1600,    sizeof(hash_cost_params_fast_t), shake128_cost},
    { "shake256",    HASH_PRIM_KECCAK1600,    sizeof(hash_cost_params_fast_t), shake256_cost},
    { "kmac128",     HASH_PRIM_KECCAK1600,    sizeof(hash_cost_params_fast_t), kmac128_cost },
    { "kmac256",     HASH_PRIM_KECCAK1600,    sizeof(hash_cost_params_fast_t), kmac256_cost },
    /* ---- National standard ------------------------------------------- */
    { "sm3",         HASH_PRIM_SM3,           sizeof(hash_cost_params_fast_t), sm3_cost     },
    /* ---- Memory-hard ------------------------------------------------- */
    { "argon2id",    HASH_PRIM_ARGON2G,       sizeof(hash_cost_params_argon2_t),  argon2_cost  },
    { "argon2i",     HASH_PRIM_ARGON2G,       sizeof(hash_cost_params_argon2_t),  argon2i_cost },
    { "argon2d",     HASH_PRIM_ARGON2G,       sizeof(hash_cost_params_argon2_t),  argon2_cost  },
    { "scrypt",      HASH_PRIM_SALSA20_8,     sizeof(hash_cost_params_scrypt_t),  scrypt_cost  },
    { "yescrypt",    HASH_PRIM_SALSA20_8,     sizeof(hash_cost_params_yescrypt_t),yescrypt_cost},
    { "bcrypt",      HASH_PRIM_BLOWFISH_KS,   sizeof(hash_cost_params_bcrypt_t),  bcrypt_cost  },
    { "catena",      HASH_PRIM_BLAKE2B,       sizeof(hash_cost_params_catena_t),  catena_cost  },
    { "lyra2",       HASH_PRIM_BLAKMA,        sizeof(hash_cost_params_lyra2_t),   lyra2_cost   },
    { "balloon",     HASH_PRIM_SHA256_COMP,   sizeof(hash_cost_params_balloon_t), balloon_cost },
    { "pomelo",      HASH_PRIM_POMELO_F,      sizeof(hash_cost_params_pomelo_t),  pomelo_cost  },
    { "makwa",       HASH_PRIM_MONTGOMERY,    sizeof(hash_cost_params_makwa_t),   makwa_cost   },
    /* ---- Skein ------------------------------------------------------- */
    { "skein256",    HASH_PRIM_THREEFISH256,  sizeof(hash_cost_params_fast_t), skein256_cost},
    { "skein512",    HASH_PRIM_THREEFISH512,  sizeof(hash_cost_params_fast_t), skein512_cost},
    { "skein1024",   HASH_PRIM_THREEFISH1024, sizeof(hash_cost_params_fast_t), skein1024_cost},
    /* ---- Legacy ------------------------------------------------------ */
    { "sha1",        HASH_PRIM_SHA256,        sizeof(hash_cost_params_fast_t), sha1_cost    },
    { "sha0",        HASH_PRIM_SHA256,        sizeof(hash_cost_params_fast_t), sha1_cost    },
    { "md5",         HASH_PRIM_SHA256,        sizeof(hash_cost_params_fast_t), md5_cost     },
    { "md4",         HASH_PRIM_SHA256,        sizeof(hash_cost_params_fast_t), md4_cost     },
    { "md2",         HASH_PRIM_SHA256,        sizeof(hash_cost_params_fast_t), md2_cost     },
    { "nt",          HASH_PRIM_SHA256,        sizeof(hash_cost_params_fast_t), md4_cost     },
    { "has160",      HASH_PRIM_SHA256,        sizeof(hash_cost_params_fast_t), sha1_cost    },
    { "ripemd128",   HASH_PRIM_RIPEMD,        sizeof(hash_cost_params_fast_t), ripemd_cost  },
    { "ripemd160",   HASH_PRIM_RIPEMD,        sizeof(hash_cost_params_fast_t), ripemd_cost  },
    { "ripemd256",   HASH_PRIM_RIPEMD,        sizeof(hash_cost_params_fast_t), ripemd_cost  },
    { "ripemd320",   HASH_PRIM_RIPEMD,        sizeof(hash_cost_params_fast_t), ripemd_cost  },
    { "whirlpool",   HASH_PRIM_WHIRLPOOL,     sizeof(hash_cost_params_fast_t), whirlpool_cost},
    { "tiger",       HASH_PRIM_TIGER,         sizeof(hash_cost_params_fast_t), tiger_cost   },
};

#define N_PLUGINS  ((size_t)(sizeof(s_plugins) / sizeof(s_plugins[0])))

/* -----------------------------------------------------------------------
 * Registry API
 * ----------------------------------------------------------------------- */

int hash_cost_registry_init(void)
{
    /* Validate the static plugin table at startup.
     * Catches bugs where a new entry was added with a zeroed field. */
    for (size_t i = 0; i < N_PLUGINS; i++) {
        if (!s_plugins[i].name)        return -1;
        if (!s_plugins[i].compute)     return -1;
        if (!s_plugins[i].params_size) return -1;
        if (!s_plugins[i].primitive_id) return -1;
    }
    return 0;
}

const hash_cost_plugin_t *hash_cost_lookup(const char *name)
{
    if (!name) return NULL;
    for (size_t i = 0; i < N_PLUGINS; i++)
        if (strcmp(s_plugins[i].name, name) == 0) return &s_plugins[i];
    return NULL;
}

int hash_cost_compute(const char *name, const void *params,
                      size_t params_size, hash_cost_t *out)
{
    if (!params || !out) return -2;
    const hash_cost_plugin_t *pl = hash_cost_lookup(name);
    if (!pl) return -1;
    pl->compute(params, params_size, out);
    return 0;
}

size_t hash_cost_algo_count(void)
{
    return N_PLUGINS;
}
