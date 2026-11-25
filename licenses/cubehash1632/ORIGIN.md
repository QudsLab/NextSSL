# ORIGIN: cubehash1632

- package: SUPERCOP crypto_hash/cubehash1632
- source URL: https://bench.cr.yp.to/supercop/supercop-20261018.tar.xz
- sha256: 9a44c3e619632d140cbad436f5cebbea5f2b8d6efe752946c3e367c4c2ac8288
- copied verbatim from collection/supercop-crypto_hash/cubehash1632
- license: unknown (per-implementation notices kept in upstream/ where present)

## Variant switched (fix156)

The previously wired variant cellspu/ needs the Cell SPU compiler (spu_intrinsics.h) and cannot build on x86/arm. Replaced by the portable SUPERCOP variant simple/
(verbatim from supercop-20261018.tar.xz, sha256 9a44c3e6...ac8288, crypto_hash/cubehash1632/simple/: cubehash.c, cubehash.h, nist.c, nist.h, parameters.h, api.h).

## cryptoint (fix156)

upstream/cryptoint/ holds verbatim files (crypto_uint32 and their *_optblocker.c) from the pinned SUPERCOP tree
(supercop-20261018.tar.xz, sha256 9a44c3e6...ac8288), directory cryptoint/. Public domain (LicenseRef-PD-hp). It precedes compat/ on the include path.
