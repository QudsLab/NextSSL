# ORIGIN: bleep64

- package: SUPERCOP crypto_aead/bleep64
- source URL: https://bench.cr.yp.to/supercop/supercop-20261018.tar.xz
- sha256: 9a44c3e619632d140cbad436f5cebbea5f2b8d6efe752946c3e367c4c2ac8288
- copied verbatim from collection/supercop-crypto_aead/bleep64
- license: unknown (per-implementation notices kept in upstream/ where present)

## Build flag (fix156)

build.rs passes -fgnu89-inline on non-MSVC targets: upstream defines `inline int Bleep64(...)` (not static) and calls it from crypto_aead_encrypt/decrypt in the same file. Under C99 inline rules no external definition is emitted for a plain `inline` function, so the symbol is undefined at link time (it is used by the exported functions only if the compiler does not inline it). GNU89 semantics emit it. No upstream file edited.
- build-time portability rewrite (owner review pending, rule 1): ref/encrypt.c is compiled from a copy made by build.rs in which the GCC nested function crypt(odd, assoc) becomes a statement macro with the same body (all 9 calls pass literal 0/1; the body uses the enclosing locals as before). The file in upstream/ is unchanged.
