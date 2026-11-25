# ORIGIN: aes128poetv2aes4ni

- package: SUPERCOP crypto_aead/aes128poetv2aes4ni
- source URL: https://bench.cr.yp.to/supercop/supercop-20261018.tar.xz
- sha256: 9a44c3e619632d140cbad436f5cebbea5f2b8d6efe752946c3e367c4c2ac8288
- copied verbatim from collection/supercop-crypto_aead/aes128poetv2aes4ni
- license: unknown (per-implementation notices kept in upstream/ where present)

## Portable variant for non-x86 targets (2026-11-22)

upstream/portable/ is SUPERCOP crypto_aead/aes128poetv2aes4/ref, verbatim from the same supercop-20261018.tar.xz. SUPERCOP records the same checksumsmall and checksumbig for aes128poetv2aes4 and aes128poetv2aes4ni, so both are the same primitive. build.rs compiles ref/ (AES-NI) on x86 and portable/ everywhere else (wasm32, aarch64).
