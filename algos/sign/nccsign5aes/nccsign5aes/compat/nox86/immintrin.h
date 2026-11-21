/* NextSSL compat (not upstream), non-x86 targets only. ref/sign.h and ref/poly.h include
 * <immintrin.h> for one unused declaration, `extern __m256i mask7FFFFF, ...`; nothing defines or uses
 * those variables. The type alone is provided (no intrinsics), so any real use would fail to compile. */
#ifndef NEXTSSL_COMPAT_IMMINTRIN_H
#define NEXTSSL_COMPAT_IMMINTRIN_H
typedef struct { long long nextssl_lanes[4]; } __m256i;
#endif
