# ORIGIN: keccakc256treed2

- package: SUPERCOP crypto_hash/keccakc256treed2
- source URL: https://bench.cr.yp.to/supercop/supercop-20261018.tar.xz
- sha256: 9a44c3e619632d140cbad436f5cebbea5f2b8d6efe752946c3e367c4c2ac8288
- copied verbatim from collection/supercop-crypto_hash/keccakc256treed2
- license: unknown (per-implementation notices kept in upstream/ where present)

## Variant switched (fix156)

The previously wired variant xopu24/ needs AMD XOP instructions (-mxop; removed from AMD CPUs since Zen, never on Intel). Replaced by SUPERCOP's sseu24/ variant of the same
scheme (SSE2 only, baseline x86-64), verbatim from supercop-20261018.tar.xz, sha256 9a44c3e6...ac8288, crypto_hash/keccakc256treed2/sseu24/. Output size is identical (api.h equal).

build.rs passes -mssse3 on non-MSVC x86_64 targets (the sseu24 code uses _mm_shuffle_epi8; SUPERCOP's build uses -march=native).
