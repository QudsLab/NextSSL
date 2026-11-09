<div align="center"><img src="assets/logo_ud.svg" width="92%" alt="NextSSL" /></div>

# NextSSL

An open cryptographic algorithm library in Rust, built to collect as many real, programmable algorithms as possible behind one consistent API, with post-quantum algorithms first.

> **Status: early development. Do not use this in production.** The API may change, there has been no external security audit, and no binary release exists yet.

## What is in it

394 algorithms are registered today. Algorithm cores are copied from upstream projects (Rust crates or C and C++ reference code) and pinned to an exact version or commit. A small number are ported from other languages or written from the specification; those are always tier `unverified`.

| Kind | Count | Kind | Count |
|---|---:|---|---:|
| AEAD | 78 | Password hash | 15 |
| Hash | 58 | Encoding | 12 |
| Signature | 50 | Checksum | 11 |
| Block cipher | 46 | Public-key encryption | 9 |
| MAC | 28 | XOF | 8 |
| KEM | 22 | KDF | 5 |
| Stream cipher | 20 | Key agreement | 5 |
| Block mode | 17 | PAKE, stateful signature | 3 each |
| | | DRBG, RNG, threshold, ZK | 1 each |

The authoritative list, with each algorithm's tier, upstream and license, is [docs/algo.generated.json](docs/algo.generated.json).

**Test coverage varies by algorithm.** 83 of the 394 have no known-answer vectors yet and are only exercised by a round-trip smoke test. Do not assume an algorithm is correct because it is listed.

## Tiers

| Tier | Meaning | Reachable from |
|---|---|---|
| `safe` | modern, recommended | safe API and root |
| `standard` | standardised and sound | safe API and root |
| `legacy` | old, not broken | root only |
| `broken` | known attacks exist | root only |
| `research` | experimental or unclassified | root only |
| `unverified` | source or correctness not fully proven | root only |

## Usage

The safe API allows only `safe` and `standard` algorithms and produces self-describing COSE (RFC 9052) envelopes.

The root API reaches every tier. By using it, you accept the risk of the algorithm you pick:

```rust
let digest = nextssl_root::md5::hash(b"abc")?;

let (pk, sk) = nextssl_root::ml_kem_768::keygen()?;
let (ct, ss) = nextssl_root::ml_kem_768::encapsulate(&pk)?;

// Build a construction from parts by name.
let mac = nextssl_root::compose("hmac(sm3)")?;
```

API notes are in [crates/nextssl-core/API.md](crates/nextssl-core/API.md), and the envelope format is in [docs/envelope.md](docs/envelope.md).

## Verify it yourself

```bash
cargo xtask gen --check
cargo test --workspace
```

The Docker image runs the same tests with the sanitizer, Miri, fuzz and WASM layers:

```bash
docker build -f docker/Dockerfile.test -t nextssl-test .
docker run --rm nextssl-test
```

Those extra layers have not been run against every algorithm yet.

Optional cargo features: `copyleft` (GPL-family algorithms, off by default), `all-heavy` (large libraries), `compose-all` (every digest and cipher in the composition engine).

## Security

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

NextSSL is not FIPS validated.

## License

Apache-2.0 for NextSSL's own code (see [LICENSE](LICENSE)). Each algorithm keeps its upstream license in its own `upstream/` folder, and some upstream sources have no stated license: check before redistributing.
