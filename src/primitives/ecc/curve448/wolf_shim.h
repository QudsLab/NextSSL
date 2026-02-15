#ifndef WOLF_SHIM_H
#define WOLF_SHIM_H

#include <stdint.h>
#include <string.h>

// Types
typedef uint8_t word8;
typedef int8_t sword8;
typedef uint16_t word16;
typedef int16_t sword16;
typedef uint32_t word32;
typedef int32_t sword32;
typedef uint64_t word64;
typedef int64_t sword64;
typedef uint8_t byte;

#ifdef __SIZEOF_INT128__
    typedef __uint128_t uint128_t;
    typedef __int128_t int128_t;
    typedef __uint128_t word128;
    typedef __int128_t sword128;
    #define HAVE___UINT128_T
#endif

// Macros
#define XMEMCPY memcpy
#define XMEMSET memset
#define XMEMMOVE memmove
#define XMEMCMP memcmp

#define FORCE_INLINE inline
#define WC_INLINE inline

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define WC_NO_ERR_TRACE(x) (x)
#define WOLFSSL_MSG(x)
#define WC_DO_NOTHING do {} while(0)

#define ForceZero(addr, len) XMEMSET((addr), 0, (len))
#define ConstantCompare(a, b, len) XMEMCMP((a), (b), (len))

#define WOLFSSL_LOCAL
#define WOLFSSL_API

#include "../../hash/sponge_xof/shake/shake.h"
typedef SHAKE_CTX wc_Shake;

typedef struct WC_RNG WC_RNG;
typedef unsigned int WC_BITFIELD;

// Features
#ifndef HAVE_CURVE448
#define HAVE_CURVE448
#endif
#ifndef HAVE_ED448
#define HAVE_ED448
#endif
#ifndef HAVE_CURVE448_SHARED_SECRET
#define HAVE_CURVE448_SHARED_SECRET
#endif
#ifndef HAVE_CURVE448_KEY_EXPORT
#define HAVE_CURVE448_KEY_EXPORT
#endif
#ifndef HAVE_ED448_SIGN
#define HAVE_ED448_SIGN
#endif
#ifndef HAVE_ED448_VERIFY
#define HAVE_ED448_VERIFY
#endif
#ifndef HAVE_ED448_KEY_EXPORT
#define HAVE_ED448_KEY_EXPORT
#endif
#ifndef HAVE_ED448_KEY_IMPORT
#define HAVE_ED448_KEY_IMPORT
#endif
#ifndef HAVE_CURVE448_KEY_IMPORT
#define HAVE_CURVE448_KEY_IMPORT
#endif
// #define CURVE448_SMALL // Uncomment for small implementation

// Error Codes
#define ECC_BAD_ARG_E -123
#define BAD_FUNC_ARG  -173
#define MEMORY_E      -125
#define MP_INIT_E     -126
#define BUFFER_E      -132
#define SIG_VERIFY_E  -188
#define RNG_FAILURE_E -189
#define ECC_PRIV_KEY_E -190
#define PUBLIC_KEY_E  -191

#define INVALID_DEVID -2

// RNG Shim
static inline int wc_RNG_GenerateBlock(WC_RNG* rng, byte* b, word32 sz) {
    // TODO: Connect to real RNG
    // For now, fail or zero
    memset(b, 0, sz); 
    return 0; // Return 0 for success? Or implement randombytes
}

// SHAKE Shim
static inline int wc_InitShake256(wc_Shake* shake, void* heap, int devId) {
    shake256_init(shake);
    return 0;
}

static inline void wc_Shake256_Free(wc_Shake* shake) {
    (void)shake;
}

static inline int wc_Shake256_Update(wc_Shake* shake, const byte* data, word32 len) {
    shake_update(shake, data, len);
    return 0;
}

static inline int wc_Shake256_Final(wc_Shake* shake, byte* out, word32 outLen) {
    shake_squeeze(shake, out, outLen);
    return 0;
}

#endif
