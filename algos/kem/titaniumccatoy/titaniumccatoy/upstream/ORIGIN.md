# ORIGIN: titaniumccatoy

- package: SUPERCOP crypto_kem/titaniumccatoy
- source URL: https://bench.cr.yp.to/supercop/supercop-20261018.tar.xz
- sha256: 9a44c3e619632d140cbad436f5cebbea5f2b8d6efe752946c3e367c4c2ac8288
- copied verbatim from collection/supercop-crypto_kem/titaniumccatoy
- license: unknown (per-implementation notices kept in upstream/ where present)

## XKCP support files (fix156)

upstream/xkcp/ holds verbatim files from the SUPERCOP-pinned XKCP tree (supercop-20261018.tar.xz, sha256 9a44c3e6...ac8288), directory k/lib/:
high/Keccak/FIPS202/{KeccakHash,SimpleFIPS202}.{c,h}, high/Keccak/KeccakSponge.{c,h,inc}, low/KeccakP-1600/plain-64bits/{KeccakP-1600-opt64.c,KeccakP-1600-SnP.h},
plain-64bits/u6/KeccakP-1600-opt64-config.h, low/KeccakP-1600/common/*.macros, low/common/SnP-Relaned.h, common/{align,brg_endian}.h.
License: CC0 / public domain (XKCP, Keccak Team), plus BSD notice in brg_endian.h. NextSSL-authored shims (not upstream): compat/xkcp/config.h, compat/sha3/*.h, compat/libkeccak.a.headers/*.h.

## XKCP SP800-185 (fix156)

upstream/xkcp/SP800-185.{c,h,inc}: verbatim from SUPERCOP k/lib/high/Keccak/SP800-185/ (supercop-20261018.tar.xz, sha256 9a44c3e6...ac8288), CC0. Shim (ours): compat/libkeccak.a.headers/SP800-185.h.

Also upstream/xkcp/Phases.h verbatim from k/lib/high/common/Phases.h (needed by SP800-185.h).

compat/crypto_kem.h (ours) now also maps crypto_kem_*BYTES to the CRYPTO_*BYTES of api.h, as SUPERCOP's generated crypto_kem.h does; kem.c uses the crypto_kem_ spellings.
