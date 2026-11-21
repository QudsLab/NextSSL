# ORIGIN: smaugt1v5

- package: SUPERCOP crypto_kem/smaugt1v5
- source URL: https://bench.cr.yp.to/supercop/supercop-20261018.tar.xz
- sha256: 9a44c3e619632d140cbad436f5cebbea5f2b8d6efe752946c3e367c4c2ac8288
- copied verbatim from collection/supercop-crypto_kem/smaugt1v5
- license: unknown (per-implementation notices kept in upstream/ where present)

## Build define (fix156)

build.rs defines `CRYPTO_NAMESPACE(s)` as `crypto_kem_##s` on non-MSVC targets. SUPERCOP's build supplies this macro on the command line; this mapping makes the exported API names crypto_kem_keypair/enc/dec (what the NextSSL glue links to), and the symbol-prefixing pass of build.rs then isolates them. No upstream file edited.

## cryptoint (fix156)

upstream/cryptoint/ holds verbatim files (crypto_int16, crypto_int64, crypto_uint16, crypto_uint64 and their *_optblocker.c) from the pinned SUPERCOP tree
(supercop-20261018.tar.xz, sha256 9a44c3e6...ac8288), directory cryptoint/. Public domain (LicenseRef-PD-hp). It precedes compat/ on the include path.
