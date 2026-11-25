# ORIGIN: skein512256

- package: SUPERCOP crypto_hash/skein512256
- source URL: https://bench.cr.yp.to/supercop/supercop-20261018.tar.xz
- sha256: 9a44c3e619632d140cbad436f5cebbea5f2b8d6efe752946c3e367c4c2ac8288
- copied verbatim from collection/supercop-crypto_hash/skein512256
- license: unknown (per-implementation notices kept in upstream/ where present)

## Variant switched (2026-11-22)

The mmx/ variant (x86 SIMD only) was replaced by SUPERCOP's opt/ variant of the same scheme (portable C), verbatim from the same pinned supercop-20261018.tar.xz, so the algorithm builds on aarch64 and wasm32. Output checked identical to mmx/ on x86-64 (differential run).

brg_endian.h in compat/ is byte-identical to crypto_aead/hanmre/ref/brg_endian.h of the same tarball (Gladman; opt/skein_port.h includes it).
