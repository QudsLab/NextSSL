# ORIGIN: frodokem1344shake

- package: SUPERCOP crypto_kem/frodokem1344shake
- source URL: https://bench.cr.yp.to/supercop/supercop-20261018.tar.xz
- sha256: 9a44c3e619632d140cbad436f5cebbea5f2b8d6efe752946c3e367c4c2ac8288
- copied verbatim from collection/supercop-crypto_kem/frodokem1344shake
- license: unknown (per-implementation notices kept in upstream/ where present)

## Build flags (fix156)

This is SUPERCOP's x64 variant: it uses AES-NI / AVX2 intrinsics and needs -mavx2 on the compiler command line (SUPERCOP's build adds -march=native). build.rs passes them on non-MSVC x86_64 targets only. No upstream file edited. The CPU must support the instructions at run time.
