# ORIGIN: threebears936r2ccax

- package: SUPERCOP crypto_kem/threebears936r2ccax
- source URL: https://bench.cr.yp.to/supercop/supercop-20261018.tar.xz
- sha256: 9a44c3e619632d140cbad436f5cebbea5f2b8d6efe752946c3e367c4c2ac8288
- copied verbatim from collection/supercop-crypto_kem/threebears936r2ccax
- license: unknown (per-implementation notices kept in upstream/ where present)

## cryptoint (fix156)

upstream/cryptoint/ holds verbatim files (crypto_int64, crypto_uint32 and their *_optblocker.c) from the pinned SUPERCOP tree
(supercop-20261018.tar.xz, sha256 9a44c3e6...ac8288), directory cryptoint/. Public domain (LicenseRef-PD-hp). It precedes compat/ on the include path.

## XKCP support files (fix156)

upstream/xkcp/ holds verbatim files from the SUPERCOP-pinned XKCP tree (supercop-20261018.tar.xz, sha256 9a44c3e6...ac8288), directory k/lib/:
high/Keccak/FIPS202/{KeccakHash,SimpleFIPS202}.{c,h}, high/Keccak/KeccakSponge.{c,h,inc}, low/KeccakP-1600/plain-64bits/{KeccakP-1600-opt64.c,KeccakP-1600-SnP.h},
plain-64bits/u6/KeccakP-1600-opt64-config.h, low/KeccakP-1600/common/*.macros, low/common/SnP-Relaned.h, common/{align,brg_endian}.h.
License: CC0 / public domain (XKCP, Keccak Team), plus BSD notice in brg_endian.h. NextSSL-authored shims (not upstream): compat/xkcp/config.h, compat/sha3/*.h, compat/libkeccak.a.headers/*.h.
