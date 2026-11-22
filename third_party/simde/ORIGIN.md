# ORIGIN: SIMDe (SIMD Everywhere)

- project: https://github.com/simd-everywhere/simde
- release: v0.8.2, asset simde-amalgamated-0.8.2.tar.xz
- asset sha256: 59068edc3420e75c5ff85ecfd80a77196fb3a151227a666cc20abb313a5360bf
- copied verbatim: x86/avx2.h, x86/aes.h, x86/clmul.h (amalgamated, self-contained); COPYING from tag v0.8.2
- license: MIT (COPYING)
- not crypto: a portability layer that implements x86 SIMD intrinsics in portable C.
- x86-shim/ is NextSSL's: stand-ins for <immintrin.h> and friends, put on the include path only for
  non-x86 targets by the build.rs of algorithms whose only upstream implementation uses x86 SIMD.
