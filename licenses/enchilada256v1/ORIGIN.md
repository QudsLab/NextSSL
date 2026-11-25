# ORIGIN: enchilada256v1

- package: SUPERCOP crypto_aead/enchilada256v1
- source URL: https://bench.cr.yp.to/supercop/supercop-20261018.tar.xz
- sha256: 9a44c3e619632d140cbad436f5cebbea5f2b8d6efe752946c3e367c4c2ac8288
- copied verbatim from collection/supercop-crypto_aead/enchilada256v1
- license: unknown (per-implementation notices kept in upstream/ where present)

## Dependency verify16 (fix156)

upstream/deps/verify16/ holds verbatim SUPERCOP files (supercop-20261018.tar.xz, sha256 9a44c3e6...ac8288): crypto_verify/16/ref/verify.c, crypto_verify/16/ref/api.h.
Public domain (D. J. Bernstein et al.). NextSSL-authored shims (not upstream): compat/crypto_verify_16.h, compat/crypto_verify.h.

## cryptoint (fix156)

upstream/cryptoint/ holds verbatim files (crypto_int16 and their *_optblocker.c) from the pinned SUPERCOP tree
(supercop-20261018.tar.xz, sha256 9a44c3e6...ac8288), directory cryptoint/. Public domain (LicenseRef-PD-hp). It precedes compat/ on the include path.
