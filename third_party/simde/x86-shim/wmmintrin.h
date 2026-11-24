/* NextSSL (not upstream). Used ONLY on non-x86 targets (wasm32, aarch64): stands in for the compiler's
 * x86 intrinsic header so x86-SIMD upstreams build unchanged. SIMDe v0.8.2 implements every _mm_* in
 * portable C (or the target's own SIMD); SIMDE_ENABLE_NATIVE_ALIASES keeps the x86 names. x86 targets
 * never see this directory and use the real intrinsics. */
#ifndef NEXTSSL_SIMDE_X86_SHIM
#define NEXTSSL_SIMDE_X86_SHIM
/* No _Float16 on wasm32: SIMDe's portable half-float type (SIMDE_FLOAT16_API_PORTABLE). */
#ifndef SIMDE_FLOAT16_API
#define SIMDE_FLOAT16_API 1
#endif
/* x86 compilers accept a variable shift count for _mm_srli_epi64 and friends; so does SIMDe's portable code. */
#ifndef SIMDE_NO_CHECK_IMMEDIATE_CONSTANT
#define SIMDE_NO_CHECK_IMMEDIATE_CONSTANT
#endif
#ifndef SIMDE_ENABLE_NATIVE_ALIASES
#define SIMDE_ENABLE_NATIVE_ALIASES
#endif
/* clang-cl (Windows on ARM64) takes SIMDe's C11 path for _mm_sfence, atomic_thread_fence(), but
 * SIMDe does not include <stdatomic.h>; GCC and clang elsewhere use the __atomic builtin instead. */
#if defined(_MSC_VER) && defined(__clang__) && !defined(__cplusplus) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
#endif
#include "../x86/avx2.h"
#include "../x86/aes.h"
#include "../x86/clmul.h"
#endif
