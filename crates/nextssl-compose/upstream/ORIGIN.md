# ORIGIN: nextssl-compose

The engine is glue over upstream generic crates; no primitive is hand-written here.

| Constructor | Upstream |
|---|---|
| `hmac`, HMAC calls inside `hmac-drbg` | RustCrypto `hmac` =0.13.0 (MIT OR Apache-2.0) |
| `hkdf` | RustCrypto `hkdf` =0.13.0 |
| `pbkdf2` | RustCrypto `pbkdf2` =0.13.0 |
| `cmac` | RustCrypto `cmac` =0.8.0 |
| `cbc`, `ecb`, `cfb` | RustCrypto `cbc` =0.2.1, `ecb` =0.2.1, `cfb-mode` =0.9.1 |
| digest and cipher types | the crates named by the `digest` / `cipher` fields of `algos/**/algo.toml` (generated) |

## Port exception (rule 1), recorded for the owner

The three DRBGs (`src/drbg.rs`) and the hashcash stamp loop (`src/pow.rs`) have no upstream that is generic
over the RustCrypto digest 0.11 / cipher 0.5 types: the `hmac-drbg` crate needs digest 0.9, there is no
Hash_DRBG crate, `libcrux-hmac-drbg` is SHA-256 only, and `drbg` 2.0 is a different API. They are our own
state machines written from NIST SP 800-90A Rev. 1 (sections 10.1.2 HMAC_DRBG, 10.1.1 Hash_DRBG, 10.2.1
CTR_DRBG with Block_Cipher_df) and hashcash.org v1; every hash, HMAC and AES call goes to the upstream
generics or to the registered AES. This is a **Rust** port, not the C port the exception names, so it is tier
`unverified` (root only) and needs an independent review before it can leave `unverified`.
The OpenSSL (Apache-2.0) DRBG sources collected in `collection/drbg/` are the cross-check reference.

Tests: NIST CAVP `drbgtestvectors.zip` (no-reseed set, subset rule in `kat/README.md`), byte-for-byte equality
with `hmac-drbg-sha256` (libcrux) on the SHA-256 vectors, and the hashcash.org example stamp. The differential
test against OpenSSL in Docker has not been run (the Docker daemon was down).
