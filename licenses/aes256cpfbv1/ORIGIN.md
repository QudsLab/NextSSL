# ORIGIN: aes256cpfbv1

- package: SUPERCOP crypto_aead/aes256cpfbv1
- source URL: https://bench.cr.yp.to/supercop/supercop-20261018.tar.xz
- sha256: 9a44c3e619632d140cbad436f5cebbea5f2b8d6efe752946c3e367c4c2ac8288
- copied verbatim from collection/supercop-crypto_aead/aes256cpfbv1
- license: unknown (per-implementation notices kept in upstream/ where present)

## Dependency aes256encrypt (fix156)

upstream/deps/aes256encrypt/ holds verbatim SUPERCOP files (supercop-20261018.tar.xz, sha256 9a44c3e6...ac8288): crypto_core/aes256encrypt/ref/core.c, crypto_core/aes256encrypt/ref/api.h.
Public domain (D. J. Bernstein et al.). NextSSL-authored shims (not upstream): compat/crypto_core_aes256encrypt.h, compat/crypto_core.h.

## cryptoint (fix156)

upstream/cryptoint/ holds verbatim files (crypto_int64, crypto_uint32 and their *_optblocker.c) from the pinned SUPERCOP tree
(supercop-20261018.tar.xz, sha256 9a44c3e6...ac8288), directory cryptoint/. Public domain (LicenseRef-PD-hp). It precedes compat/ on the include path.
