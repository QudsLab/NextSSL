# ORIGIN: groestl512

- package: SUPERCOP crypto_hash/groestl512
- source URL: https://bench.cr.yp.to/supercop/supercop-20261018.tar.xz
- sha256: 9a44c3e619632d140cbad436f5cebbea5f2b8d6efe752946c3e367c4c2ac8288
- copied verbatim from collection/supercop-crypto_hash/groestl512
- license: unknown (per-implementation notices kept in upstream/ where present)

## Support file brg_endian.h (fix156)

upstream/support/brg_endian.h: verbatim copy of Brian Gladman's brg_endian.h as shipped in the pinned SUPERCOP tree (supercop-20261018.tar.xz, sha256 9a44c3e6...ac8288), crypto_kem/threebears1248r2cca/opt/brg_endian.h (identical to the copy in many SUPERCOP implementations). BSD-style license in the file header.

## cryptoint (fix156)

upstream/cryptoint/ holds verbatim files (crypto_uint32, crypto_uint64, crypto_uint8 and their *_optblocker.c) from the pinned SUPERCOP tree
(supercop-20261018.tar.xz, sha256 9a44c3e6...ac8288), directory cryptoint/. Public domain (LicenseRef-PD-hp). It precedes compat/ on the include path.

## Variant switched (fix156)

The previously wired core2duo/ variant uses hand-written x86-64 inline asm with absolute (non-PIC) table references (`T0 can not be used when making a PIE object`),
so it cannot be linked into a PIE/shared object. Replaced by SUPERCOP's portable C variant opt64/ of the same scheme, verbatim from supercop-20261018.tar.xz,
sha256 9a44c3e6...ac8288, crypto_hash/groestl512/opt64/ (hash.c, hash.h, tables.h, brg_types.h, api.h, README).

## Build flag (fix156)

build.rs passes -fgnu89-inline on non-MSVC targets: the opt64 sources declare `inline` helper functions (F512/F1024) without static; under C99 inline rules no external definition is emitted and the link fails. No upstream file edited.
