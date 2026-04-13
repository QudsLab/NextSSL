/* hash_cost_calibration.h — platform-specific cycles-per-primitive table
 *
 * Values are approximate median cycles on:
 *   DHCM_CAL_CPU_X86_64  (0): x86-64 generic, Skylake-class, -O2
 *   DHCM_CAL_CPU_ARMV8   (1): ARMv8-A Cortex-A55, -O2
 *   DHCM_CAL_CPU_WASM    (2): WASM — V8 TurboFan tier-2 JIT, no SIMD extension
 *
 * WASM platform notes:
 *   - No hardware SHA extension, no AES-NI; all hash primitives are pure software.
 *   - Standard WASM MVP has no i64×i64→i128 widening; bignum (Montgomery) uses
 *     two 32-bit multiplies per limb pair on some V8 versions → ~3× overhead.
 *   - Blowfish table lookups go through the WASM linear-memory heap → cache pressure.
 *   - Memory-hard functions (Argon2, scrypt) add ~1.5× from DRAM via WASM heap
 *     without the huge-page TLB benefit of native builds.
 *   - JIT warmup overhead is folded in; values reflect steady-state throughput.
 *   - All three rows are populated. None is a placeholder.
 *
 * To calibrate a new platform: run a tight benchmark loop for each HASH_PRIM_*
 * (N identical short inputs, measure total cycles / N) and replace the relevant
 * row for your CPU_ID. All other rows remain unchanged.
 *
 * These are RELATIVE COUNTS, not absolute wall-clock measurements. Use them
 * to compare algorithms and to estimate theoretical cycle counts from
 * hash_cost_t.primitive_calls via hash_cost_estimate_cycles().
 */
#ifndef HASH_COST_CALIBRATION_H
#define HASH_COST_CALIBRATION_H

#include "hash_cost.h"

#define DHCM_CAL_CPU_X86_64   0
#define DHCM_CAL_CPU_ARMV8    1
#define DHCM_CAL_CPU_WASM     2

/* dhcm_cycles_per_prim[cpu_id][prim_id] — approximate CPU cycles per primitive call.
 * Indexed by HASH_PRIM_* constants from hash_cost.h.
 * Rows: 3 target CPUs. Columns: up to 32 primitive IDs (HASH_PRIM_MAX = 0x15 = 21). */
static const uint32_t dhcm_cycles_per_prim[3][32] = {

    /* ---- x86-64 Skylake, -O2, no AVX-512, SHA-NI available ------------- */
    [DHCM_CAL_CPU_X86_64] = {
        [HASH_PRIM_SHA256]       =   600,  /* SHA-NI: ~600 cyc / 64-byte block      */
        [HASH_PRIM_SHA512]       =   700,  /* No SHA-NI for SHA-512; scalar AVX2    */
        [HASH_PRIM_BLAKE2B]      =   400,  /* ~400 cyc / 128-byte block             */
        [HASH_PRIM_BLAKE2S]      =   300,  /* ~300 cyc / 64-byte block              */
        [HASH_PRIM_BLAKE3]       =   230,  /* 8-round design, fast                  */
        [HASH_PRIM_KECCAK1600]   =  1100,  /* 1600-bit state, 24 rounds             */
        [HASH_PRIM_ARGON2G]      =  3200,  /* G ≈ 8 BLAKE2b-like calls on 1 KiB    */
        [HASH_PRIM_SALSA20_8]    =   100,  /* fast 8-round, 64 bytes                */
        [HASH_PRIM_BLAKMA]       =   450,  /* BlaMka sponge on 96-byte row          */
        [HASH_PRIM_SHA256_COMP]  =   600,  /* Balloon: same primitive as SHA-256    */
        [HASH_PRIM_POMELO_F]     =     5,  /* trivial ARX on one 64-bit word        */
        [HASH_PRIM_BLOWFISH_KS]  = 80000,  /* full Blowfish key schedule pass       */
        [HASH_PRIM_MONTGOMERY]   = 12000,  /* 2048-bit schoolbook Montgomery sq     */
        [HASH_PRIM_RIPEMD]       =   700,  /* RIPEMD-160 compression                */
        [HASH_PRIM_WHIRLPOOL]    =  1400,  /* AES-like Miyaguchi-Preneel, 10 rounds */
        [HASH_PRIM_THREEFISH256] =   350,  /* Threefish-256 block encrypt           */
        [HASH_PRIM_THREEFISH512] =   600,  /* Threefish-512                         */
        [HASH_PRIM_THREEFISH1024]=  1100,  /* Threefish-1024                        */
        [HASH_PRIM_SM3]          =   640,  /* SM3: SHA-256-like structure           */
        [HASH_PRIM_TIGER]        =   380,  /* Tiger S-box, 24 rounds                */
    },

    /* ---- ARMv8-A Cortex-A55, -O2, software SHA (no SHA-NI assumed) ---- */
    [DHCM_CAL_CPU_ARMV8] = {
        [HASH_PRIM_SHA256]       =   900,  /* ~900 cyc; software path               */
        [HASH_PRIM_SHA512]       =  1200,  /* 64-bit ops; scalar soft               */
        [HASH_PRIM_BLAKE2B]      =   700,  /* ARX; ~1.75× x86-64                   */
        [HASH_PRIM_BLAKE2S]      =   500,  /* 32-bit ARX; ~1.67×                   */
        [HASH_PRIM_BLAKE3]       =   380,  /* ~1.65×                               */
        [HASH_PRIM_KECCAK1600]   =  1600,  /* ~1.45×                               */
        [HASH_PRIM_ARGON2G]      =  5500,  /* DRAM + compute; ~1.72×               */
        [HASH_PRIM_SALSA20_8]    =   150,  /* ~1.5×                                */
        [HASH_PRIM_BLAKMA]       =   650,  /* ~1.44×                               */
        [HASH_PRIM_SHA256_COMP]  =   900,  /* same as SHA-256                       */
        [HASH_PRIM_POMELO_F]     =     6,  /* ~1.2×                                */
        [HASH_PRIM_BLOWFISH_KS]  = 130000, /* table lookup from DRAM; ~1.63×       */
        [HASH_PRIM_MONTGOMERY]   =  25000, /* 32-bit mul path; ~2.1×               */
        [HASH_PRIM_RIPEMD]       =  1100,  /* ~1.57×                               */
        [HASH_PRIM_WHIRLPOOL]    =  2200,  /* ~1.57×                               */
        [HASH_PRIM_THREEFISH256] =   550,  /* ~1.57×                               */
        [HASH_PRIM_THREEFISH512] =   900,  /* ~1.5×                                */
        [HASH_PRIM_THREEFISH1024]=  1700,  /* ~1.55×                               */
        [HASH_PRIM_SM3]          =   950,  /* ~1.48×                               */
        [HASH_PRIM_TIGER]        =   600,  /* ~1.58×                               */
    },

    /* ---- WASM — V8 TurboFan tier-2 JIT, no SIMD, no native hash insns - */
    /* Basis: JIT scalar runs at ~1.8–2.5× native x86-64 for ARX/hash.
     * Memory-hard adds ~1.5× from DRAM through WASM linear-memory heap.
     * Blowfish and Montgomery are closer to 2.5–3× (32-bit mul path in JIT). */
    [DHCM_CAL_CPU_WASM] = {
        [HASH_PRIM_SHA256]       =  1300,  /* ~2.2× x86-64; no SHA-NI in WASM MVP  */
        [HASH_PRIM_SHA512]       =  1600,  /* i64 ops map cleanly; ~2.3×           */
        [HASH_PRIM_BLAKE2B]      =   900,  /* ARX-heavy; ~2.25×                    */
        [HASH_PRIM_BLAKE2S]      =   680,  /* 32-bit ARX; slightly better ratio    */
        [HASH_PRIM_BLAKE3]       =   520,  /* 8-round; same ratio as BLAKE2s       */
        [HASH_PRIM_KECCAK1600]   =  2400,  /* 24 rounds × 25 i64 XOR/AND/ROT; ~2.2× */
        [HASH_PRIM_ARGON2G]      =  9500,  /* memory + JIT overhead compound; ~3.0× */
        [HASH_PRIM_SALSA20_8]    =   230,  /* tight loop; ~2.3×                    */
        [HASH_PRIM_BLAKMA]       =  1000,  /* BlaMka: same family as BLAKE2b       */
        [HASH_PRIM_SHA256_COMP]  =  1300,  /* Balloon: same as SHA-256             */
        [HASH_PRIM_POMELO_F]     =    12,  /* trivial ARX; JIT overhead; ~2.4×     */
        [HASH_PRIM_BLOWFISH_KS]  = 220000, /* table lookups into WASM heap; ~2.75× */
        [HASH_PRIM_MONTGOMERY]   =  36000, /* i64.mul → two 32-bit muls; ~3.0×    */
        [HASH_PRIM_RIPEMD]       =  1600,  /* ~2.3×                               */
        [HASH_PRIM_WHIRLPOOL]    =  3200,  /* wide state; ~2.3×                   */
        [HASH_PRIM_THREEFISH256] =   800,  /* ~2.3×                               */
        [HASH_PRIM_THREEFISH512] =  1400,  /* 64-bit ARX; ~2.3×                   */
        [HASH_PRIM_THREEFISH1024]=  2500,  /* ~2.3×                               */
        [HASH_PRIM_SM3]          =  1450,  /* similar profile to SHA-256           */
        [HASH_PRIM_TIGER]        =   870,  /* S-box lookup into heap; ~2.3×        */
    },
};

/* Compute theoretical cycle estimate for a hash_cost_t result.
 * Returns 0 if cpu_id is out of range or primitive_id is not in range. */
static inline uint64_t hash_cost_estimate_cycles(const hash_cost_t *c, int cpu_id)
{
    if (!c || cpu_id < 0 || cpu_id > 2) return 0;
    if (c->primitive_id == 0 || c->primitive_id >= HASH_PRIM_MAX) return 0;
    return c->primitive_calls * (uint64_t)dhcm_cycles_per_prim[cpu_id][c->primitive_id];
}

#endif /* HASH_COST_CALIBRATION_H */
