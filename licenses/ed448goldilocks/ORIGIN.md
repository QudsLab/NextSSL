# ORIGIN: ed448goldilocks

- package: SUPERCOP crypto_sign/ed448goldilocks
- source URL: https://bench.cr.yp.to/supercop/supercop-20261018.tar.xz
- sha256: 9a44c3e619632d140cbad436f5cebbea5f2b8d6efe752946c3e367c4c2ac8288
- copied verbatim from collection/supercop-crypto_sign/ed448goldilocks
- license: unknown (per-implementation notices kept in upstream/ where present)
- build-time entropy rewrite (owner review pending, rule 1): 32/goldilocks.c is compiled from a copy made by build.rs: goldilocks_keygen takes its seed from randombytes (shim.c, the caller EntropySource) instead of the global crandom seeded from /dev/urandom, and goldilocks_init seeds that now unused generator from a constant instead of opening /dev/urandom. The file in upstream/ is unchanged.
