# NextSSL from Rust (direct crate use)

Example: `examples/rust/` (a standalone Cargo package; `src/main.rs` is about 300 lines, no `unsafe`, no C ABI).
It calls the registry by algorithm name and runs a demo for eleven kinds: hash, xof, checksum, encoding, mac, kdf,
aead, kem, kex, sign and rng. The C ABI in [c-abi.md](c-abi.md) is the same registry seen from C; from Rust you use the
crates directly.

## Crates

| Crate | Use it for |
|---|---|
| `nextssl` | the safe API: `hash`, `encode`, `decode`, COSE envelopes (`encrypt_with_key`, `sign`, ...), `safe`/`standard` tiers only |
| `nextssl-root` | the same calls for every tier, plus generic by-name functions (`mac`, `kdf`, `aead_seal`, `kem_keygen`, `sign_keygen`, ...) and one module per algorithm (`nextssl_root::sha256::hash`) |
| `nextssl-registry` | the table of algorithms (`all()`, `lookup`) and typed constructors per kind (`new_hash_in`, `new_kem_in`, ...) with an explicit `Policy` |
| `nextssl-core` | traits (`Hash`, `Aead`, `Kem`, `Sign`, ...), key types (`SymmetricKey`, `PrivateKey`, ...), `Params`, `Error`, `Tier`, `Kind` |

The example uses the registry directly because `Policy::Safe` and `Policy::Any` then share one code path;
`nextssl::hash` and `nextssl_root::hash` give the same digest (the demo checks that).

## Build and run

```
cd examples/rust
cargo run --release -- --list                 # 367 algorithms (default features)
cargo run --release -- --list kem
cargo run --release -- sha256                 # demo (safe policy)
cargo run --release -- ml-kem-768
cargo run --release -- --root md5             # other tiers need --root
cargo run --release -- --params hash=sha512 hmac
cargo run --release -- --info ml-dsa-65
cargo run --release --features everything -- --list    # 386: copyleft and heavy algorithms too
```

The package has its own `[workspace]` and `Cargo.lock` (copied from the main lock so versions match), like `fuzz/`.
The first build compiles every algorithm crate and takes a few minutes. In Docker:

```
docker run --rm -v "$PWD":/src -v nsl-cargo:/usr/local/cargo/registry -v nsl-target:/tmp/target \
    -e CARGO_TARGET_DIR=/tmp/target -w /src/examples/rust nextssl-test cargo run --release -- sha256
```

Exit status is the NextSSL error code (`Error::code()`), so `md5` without `--root` exits 3.

## API by kind (registry level)

```rust
use nextssl_core::{Params, Len, SymmetricKey};
use nextssl_registry::{self as reg, Policy};

let digest = reg::hash_in(reg::all(), Policy::Safe, "sha256", &Params::new(), b"abc")?;
let mut rng = reg::new_rng_in(reg::all(), Policy::Safe, "os-entropy", &Params::new())?;
let kem = reg::new_kem_in(reg::all(), Policy::Safe, "ml-kem-768", &Params::new())?;
let (pk, sk) = kem.keygen(&mut *rng)?;
let (ct, ss) = kem.encaps(&pk, &mut *rng)?;
assert_eq!(ss, kem.decaps(&sk, &ct)?);          // constant-time comparison
```

| Kind | Constructor | Operation |
|---|---|---|
| hash, encoding | `hash_in`, `encode_in`, `decode_in` | one call |
| xof, checksum | `new_xof_in`, `new_checksum_in` | `squeeze`, `checksum` |
| mac, kdf | `new_mac_in`, `new_kdf_in` | `tag`/`verify`, `derive` |
| pwhash | `new_pwhash_in` | `hash` (PHC string), `verify`, `derive` |
| aead, blockcipher, streamcipher, blockmode, mode | `new_aead_in`, ... | `seal`/`open`, `encrypt_block`, `apply_keystream`, `encrypt`/`decrypt` |
| kem, kex, sign | `new_kem_in`, `new_kex_in`, `new_sign_in` | `keygen`/`encaps`/`decaps`, `keypair`/`agree`, `keygen`/`sign`/`verify` |
| rng, drbg | `new_rng_in`, `new_drbg_in` | `fill`; `instantiate`/`generate`/`reseed` |
| pke, pake, statefulsign, zk, threshold, vdf, he, pow | `new_pke_in`, ... | see the traits in `nextssl-core/src/traits.rs`; `Policy::Any` only (root-only kinds) |

`nextssl-root` also has the by-name helpers, for example
`nextssl_root::mac("hmac", &key, data)`, `nextssl_root::kem_keygen("ml-kem-768")`, `nextssl_root::sign_keygen("ed25519")`,
and the `_with(&Params, ...)` forms that take parameters.

## Tiers and root access

`Policy::Safe` admits `safe` and `standard`; anything else is `Error::TierNotAllowed(tier)`. `Policy::Any` (what
`nextssl_root` uses) admits every tier. Root-only kinds are refused under `Policy::Safe` whatever their tier.
`reg::allowed(tier, policy)` is the check.

## Error handling

All functions return `Result<_, nextssl_core::Error>`. `Error` implements `Display` and `std::error::Error` and has a
stable `code()` (the same numbers as the C ABI). Verification returns `Ok(false)` for a well-formed but invalid
signature or tag and `Err` for malformed input; AEAD `open` returns `Err(Error::AuthenticationFailed)` and no plaintext.

## Buffer sizes and secrets

Rust callers pass slices and get `Vec<u8>` back; sizes are validated against each algorithm's `sizes()` and
`algo.toml`. Key types (`SymmetricKey`, `PrivateKey`, `SharedSecret`, `Seed`, `StatefulKey`, `Share`) zeroize on drop,
compare in constant time and never print their contents; use `Zeroizing<Vec<u8>>` for scratch secrets.

## Platform notes

Windows, Linux and macOS all build with a stable Rust toolchain and a C compiler for the C-backed algorithms (MSVC,
gcc or clang). Tested: Linux x86_64 in the `nextssl-test` Docker image (Rust 1.99.1, release build, default features).
The library workspace itself also builds and passes `cargo test -p nextssl-ffi` on Windows 11 (MSVC, same Rust).
