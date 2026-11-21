# ORIGIN: sikep751comp

- package: SUPERCOP crypto_kem/sikep751comp
- source URL: https://bench.cr.yp.to/supercop/supercop-20261018.tar.xz
- sha256: 9a44c3e619632d140cbad436f5cebbea5f2b8d6efe752946c3e367c4c2ac8288
- copied verbatim from collection/supercop-crypto_kem/sikep751comp
- license: unknown (per-implementation notices kept in upstream/ where present)

## Include path (fix156)

build.rs adds upstream/amd64 to the include path: the package's *_compressed_api.h (verbatim, part of the SUPERCOP package) lives there and the arm/ sources include it. No file edited.
