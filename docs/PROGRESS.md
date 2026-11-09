# NextSSL progress log

This is a running log of every big step, written for the site builder (NextSSL-Web) and for anyone else catching up.
Each entry says what changed, why, and the verified numbers. Numbers are copied from real command output.
The site must not claim more than this file and `docs/algo.generated.json` say.

## What NextSSL is now (one paragraph for the site)
NextSSL is a Rust library. Algorithm cores are copied verbatim from trusted upstreams (Rust crates or C reference
code, pinned to exact versions or commits) and wrapped behind a safe Rust API.
- **Safe API:** `nextssl::encrypt`, `sign`, `kem`, `hash`, `encode`, ... It only allows `safe`/`standard` tiers and returns self-describing COSE envelopes. The text form looks like `nxs1.…`.
- **Root API:** `nextssl_root`. It reaches every tier, including `legacy`, `broken`, `research` and `unverified`.
- **Source of truth:** every algorithm is one folder `algos/<category>/<family>/<id>/` with an `algo.toml`. `cargo xtask gen` builds the registry and `docs/algo.generated.json` from those files. The site's Archive page should read that JSON.

## Tiers (for the stamps on the site)
| Tier | Meaning | Reachable from |
|---|---|---|
| safe | modern, recommended default | safe API + root |
| standard | standardised and sound | safe API + root |
| legacy | old but not broken | root only |
| broken | known attacks exist | root only |
| research | experimental or not yet classified | root only |
| unverified | source found but not fully proven, or a port from another language | root only |

## Log

### 2026-11-07: P0 skeleton
- **Removed:** the old C library. It had known bugs and survives only in git history.
- **New Cargo workspace crates:** core, registry, nextssl, nextssl-root, nextssl-ffi, nextssl-wasm.
- **New tooling:** the `xtask` tool, a Docker test image, CI config and fuzz targets.
- **Scope:** 776 catalogued entries classified in `scope_classification.csv`: 658 KEEP, 76 KEEP-PROTOCOL, 32 KEEP-PLATFORM, 10 DROP.

### 2026-11-08: P1a API freeze
- **Algorithms:** 18, at least one per kind: AEAD, KEM, KEX, Sign, MAC, KDF, PwHash, XOF, block, stream, RNG, DRBG, hash, encoding. They include ML-KEM-768 and ML-DSA-65, both tested with NIST ACVP vectors.
- **Envelope:** COSE (RFC 9052). The decoder has size and nesting limits and rejects downgrades.
- **Keygen engines:** two, one seed-based and one password-based (Argon2id).
- **Interfaces:** the safe API, the root API, and an FFI with a C header.
- **Verified:** 133 tests passed, clippy clean. The agent reported Docker sanitizers, Miri, fuzz and wasm as passing.

### 2026-11-08: P2 source mapping
- **Upstreams proposed:** for every KEEP entry, in `docs/p2/sources_A.csv`, `sources_B.csv` and `sources_C.csv`. A retry for missing ones is in `sources_B_none_retry.csv`.

  | Group | Rust crate | C | none |
  |---|---|---|---|
  | A: hash / MAC / KDF / encoding | 123 | 45 | 25 |
  | B: ciphers | 61 | 25 | 108 |
  | B retry | +41 found | | 67 still none |
  | C: KEM / sign / RNG | 52 | 70 | 40 |

- **Owner rules added:**
  - Search wide before giving up. Not found anywhere means the algorithm is not added.
  - Found but unproven means tier `unverified`.
  - C++ sources are used verbatim.
  - Sources only in Java, Go, Python and similar languages are ported to C as `unverified`, with a differential test against the original.

### 2026-11-08: P2 batch 1, hash + XOF (Rust crates)
- **Imported:** 41 algorithms. **Total:** 60.
- **Hash:** MD2/4/5, SHA-1, the rest of SHA-2, SHA-3, Keccak, BLAKE2s/bp/sp, BLAKE3, Groestl, JH, Skein, SM3, Streebog, RIPEMD-128/160/256/320, Whirlpool, Tiger, GOST R 34.11-94, NT-hash and LM-hash.
- **XOF:** SHAKE128, cSHAKE128/256, ParallelHash, KangarooTwelve.
- **Blocked (5):**
  - BLAKE2b duplicates an existing alias.
  - TupleHash128/256 need a tuple input shape.
  - Poseidon and Pedersen need a parameter-set decision.
- **Verified by the main session:** `gen --check` reported "60 algorithms ok". 188 tests passed, 0 failed.
- **Follow-up:** the RIPEMD-128/256/320 KATs must be re-downloaded from the original source. SHA-2 and SHA-3 should also get raw NIST CAVP files.

### 2026-11-08: P2 batch 2, MAC / password hash / checksum / encoding (Rust crates)
- **Imported:** 42 algorithms, bringing the total to **102**.
  - **MAC:** HMAC-SHA1/SHA512/MD5/SHA3, KMAC and KMACXOF, AES-CMAC, AES-PMAC, Poly1305, keyed BLAKE2b/2s/3.
  - **Password hash:** PBKDF2 (SHA1/256/512), scrypt, Argon2d and Argon2i, bcrypt, sha256crypt, sha512crypt, Balloon.
  - **Checksum:** CRC-8/16/32/32C/64, Adler-32, Fletcher-16/32.
  - **Encoding:** Base16, Base32, Base32hex, Base64url, Base58, Base58Check, Base91.
- **Unverified tier:** Balloon and Base91. No independent vectors exist for either.
- **Blocked (29):**
  - Generic `hmac`, `pbkdf2` and `hkdf` need a string parameter with a default.
  - bech32 needs an HRP parameter.
  - base85 and base62: the crate implements the wrong variant.
  - PEM, DER and PKCS: these belong to the PKI phase.
  - The registry smoke test is too rigid for GHASH, CBC-MAC and DES-MAC.
  - HKDF-Expand-Label, BIP-32 and SLIP-10 need another KDF input shape.
- **Verified by the main session:** `gen --check` reported "102 algorithms ok". 330 tests passed, 0 failed.
- **Heavy KATs:** PBKDF2 with 16.7M iterations and scrypt at 1 GiB passed once in release mode, per the agent.

### 2026-11-08: P2 infrastructure batch (flat root accessors, enum/string params, smoke test, blocked rows)
- **Flat root accessors:** `cargo xtask gen` now writes `crates/nextssl-root/src/generated.rs`: one module per algorithm id (`sha3-256` -> `sha3_256`, ids starting with a digit get `a_`), for example `nextssl_root::md5::hash(data)`, `hmac::tag(key, data)`, `aes_256_gcm::encrypt(key, pt, aad)`, `ml_kem_768::{keygen, encapsulate, decapsulate}`, `ed25519::{keygen, sign, verify}`, plus `ID` and `INFO`. `*_with(params, ..)` forms take explicit parameters. `gen` fails if two ids map to one module or a module name collides with a root item, and a generated test checks that every registered id has a module.
- **Root string API:** new thin functions in `nextssl-root` for xof, checksum, mac, kdf, password hashes, raw AEAD, block and stream ciphers, KEM, KEX and signature key generation, and `decrypt_as` (an envelope must name the expected AEAD).
- **Params:** `algo.toml` can declare `type = "enum"` (closed value list, optional default) and required `str` params with a `test_value`. An unknown enum value is an error, never a fallback. Existing `algo.toml` files are unchanged.
- **Smoke test:** the generic registry test now takes MAC key and message lengths and KDF salt, info and output lengths from the declared sizes (new `[sizes] info`, `salt = 0`, `block`), and runs every enum value of every algorithm.
- **Re-imported (10 ids, now 112 algorithms):** `hmac`, `hkdf`, `pbkdf2` (generic over a hash enum), `hkdf-extract`, `hkdf-expand`, `bech32`, `bech32m` (required `hrp`), `ghash`, `cbc-mac`, `des-mac`. Aliases added: `omac`, `kmac128-mac`, `kmac256-mac`.
- **Still blocked:** bip32, slip10, hkdf-expand-label, kdf-tls13, crc16-ccitt/crc64 variants, base85, base62, PEM/DER/PKCS/SPKI.
- **Verified by the agent:** `gen --check` reported "112 algorithms ok". `cargo test --workspace` passed 373 tests, 0 failed. Clippy with `-D warnings` was clean. Not run: sanitizers, Miri, fuzz, Docker.

### 2026-11-08: P2 batch A3 (C upstream rows)
- **Imported (22 ids, registry now 133 algorithms):** hashes `sha0` (broken), `has160`, and the SHA-3 candidates `cubehash`, `echo`, `simd`, `fugue`, `hamsi`, `luffa`, `shabal`, `bmw`, `shavite3` (sphlib, 28/32/48/64-byte variants, tier research); checksums `xxhash32`, `xxhash64`, `xxh3`; MACs `siphash-2-4` (alias `siphash`), `siphash-4-8`, `ascon-mac`, `ascon-prf`, `chaskey` (Chaskey-12); password hash `yescrypt`; `md6` (tier unverified).
- **How:** every algorithm is the upstream C copied verbatim into `upstream/` with its licence. Exported symbols get the `nextssl__<id>__` prefix through `-D` defines in `build.rs`. A small `shim.c` per algorithm is our glue, not upstream code.
- **KATs:** sphlib families use the NIST SHA-3 competition digests from the author's own tests (24 lengths x 4 variants each). xxHash, SipHash 2-4, Ascon, yescrypt and Chaskey use the authors' published vectors. SipHash 4-8 uses OpenSSL as an independent source. HAS-160 uses the standard's vectors. SHA-0 uses the FIPS 180 (1993) examples. MD6 has only two same-code vectors, hence `unverified`.
- **Blocked (31 rows):** 15 OpenSSL KDF rows (the code depends on libcrypto internals), Botan/Crypto++ C++ rows (more than 15 files), haraka (x86 AES-NI only), highwayhash, vmac, mgf1, lyra2 (no licence), catena (Linux only), md5crypt/bsdicrypt (autotools, LGPL), BER/CER. Crate routes exist for concat-kdf/sskdf/onestep, x963 and sp800-108.
- **Verified by the agent:** `gen --check` "133 algorithms ok", clippy `-D warnings` clean, `cargo test --workspace` 424 tests passed, 0 failed, `cargo xtask check-symbols` in Docker PASS (22 C upstreams). Not run: sanitizers, Miri, fuzz, wasm.

### 2026-11-08: P2 batch B (crate rows)
- **Imported (78 new ids, registry now 211 algorithms):**
  - Block ciphers (27): `aes-128`, `aes-192`, `aria-128/192/256`, `camellia-128/192/256`, `sm4`, `kuznyechik`, `magma`, `threefish-256/512/1024` (optional 16-byte `tweak` param), `des` (broken), `3des`, `blowfish`, `twofish`, `serpent-128/192/256`, `cast5`, `cast6`, `idea`, `rc2` (broken, `effective_bits` param), `rc5` (RC5-32/12/16), `belt`.
  - Stream ciphers (14): `xchacha20`, `salsa20`, `xsalsa20`, `salsa20-8`, `salsa20-12`, `chacha8`, `chacha12`, `rabbit`, `rc4` (broken), `aes-128-ctr`, `aes-192-ctr`, `aes-128-ofb`, `aes-192-ofb`, `aes-256-ofb`.
  - Block modes with the cipher fixed (17, new kind `blockmode`): `aes-{128,192,256}-{ecb,cbc,cfb,cfb8}`, `aes-128-xts`, `aes-256-xts`, `aes-kw`, `aes-kwp`, `aes-fpe-ff1`.
  - AEADs (16): `aes-128-gcm`, `aes-192-gcm`, `aes-{128,192,256}-ccm`, `aes-128-ccm-8`, `aes-128-gcm-siv`, `aes-256-gcm-siv`, `aes-siv-cmac-256/512`, `aes-{128,192,256}-eax`, `chacha20-poly1305`, `aegis128l`, `aegis256`. MAC: `aes-gmac`.
  - Password hashes `md5crypt`, `bsdicrypt` (both broken, `pwhash` crate); KDF `concat-kdf` (aliases `kda-onestep`, `sskdf`).
- **New kind `blockmode`:** a mode with the cipher fixed, because the upstream mode crates are generic over a RustCrypto cipher type and our `Mode` trait would need hand-written modes. Two methods, `encrypt` and `decrypt` (key, nonce, data). Padding is a `padding` param. Documented in `crates/nextssl-core/API.md`; root accessors `blockmode_encrypt/decrypt` and generated per-algorithm modules were added.
- **Infrastructure:** `AlgoInfo::c_backed` is generated from `algo.toml [upstream]` and replaces the hand-kept Miri skip list. `algo.toml` accepts `url` + `sha256` pins; chaskey migrated.
- **KATs:** every vector file is parsed from a downloaded published file (NIST CAVP and ACVP, RFCs, Wycheproof, the IETF AEGIS draft, ECRYPT eSTREAM, NESSIE, the authors' pages, John the Ripper tables, Crypto++ test files that cite their source). URL and sha256 are in each `kat/README.md`. No vector comes from the crate under test.
- **Blocked:** seed and lea (only single-author crates on old cipher traits with unsafe), hc256 (crate disagrees with 286 reference vectors), zuc (no independent vector file), aes-fpe-ff3-1 (fpe 0.7.0 has FF1 only), aegis-128 (not in the crate), kdf-sp800-108 (kbkdf layout needs a decision).
- **Owner decisions needed:** `aes-gmac` message layout (IV prefix, because `Mac` has no nonce argument); CCM only offers nonce 12 with tag 16 or 8 (Aead sizes are fixed per id); `salsa20` has only 2 usable eSTREAM vectors for a 256-bit key; XTS/SIV/FPE extras listed in STATUS.md.
- **Verified by the agent:** see the gate lines in `docs/p2/STATUS.md` (GATE B). Not run: sanitizers, Miri, fuzz, wasm.

### 2026-11-08: P2 batch B (C and C++ rows)
- **Imported (42 new ids from 30 rows, registry now 253 algorithms):**
  - Ascon (SP 800-232, ascon-c): `ascon-aead128`, `ascon-hash256`, `ascon-cxof128` (customization param `custom`, 0..256 bytes); `ascon-aead128a` (v1.2 Ascon-128a).
  - NIST LWC candidates (rweather/lightweight-crypto, MIT, tier research): `elephant-dumbo`, `elephant-jumbo`, `gift-cofb`, `grain-128aead`, `isap-a-128a`, `isap-k-128a`, `photon-beetle` (+ `photon-beetle-hash`), `drygascon`/`drygascon-256`, `subterranean`, `sundae` (+ `-0`, `-64`, `-128`), `spook`/`spook-su`, `pyjamask`/`pyjamask-96`, `lotus`, `locus`, `spix`, `wage`, `xoodyak` (+ `xoodyak-hash`), `romulus` and `romulus-hash` (romulusae), `tinyjambu`/`-192`/`-256` (tier broken: round-2 version).
  - Copyleft (GPL-3.0, feature `copyleft`): `sparkle-schwaemm` (Schwaemm256-128), `sparkle-esch` (Esch256).
  - Block cipher `kalyna` family (5 ids) and AEAD `norx` (NORX64-4-1), tier unverified.
- **KATs:** every LWC algorithm is checked against the designers' known-answer file from the NIST LWC submission zips (URL, zip and file sha256 in each `kat/README.md`). The check found that rweather implements the round-2 versions of Elephant, Grain-128AEAD, TinyJAMBU and Xoodyak, so those use the round-2 files. Kalyna uses the five vectors in its reference `main.c`, NORX the authors' `kat.h` (same-code, hence unverified).
- **Blocked (about 40 rows):** `skinny` (void-pointer arithmetic does not build on MSVC), `comet` and `estate` (rweather output differs from the NIST KAT), `ascon-xof128` (reference fixes the output at 64 bytes), libtomcrypt rows (more than 15 files), OpenSSL DRBG and CTS/CFB1 modes, speck/simon (CTR wrappers only), gost28147, snow3g (SIMD only), A5/1-3 (libosmocore headers), deoxys-ii/kiasu/aez/poet/hs1-siv (no vector files), C++ rows (Botan, Crypto++), gift (standalone test programs).
- **Owner decisions needed:** allow an upstream patch for a variable-length Ascon-XOF128; whether the `comet`/`estate` mismatch with rweather should be chased with the designers; the `Mode` kind for CTS/CFB1.
- **Verified by the agent:** see the gate lines at the end of `docs/p2/STATUS.md`. Windows MSVC host: gen --check, clippy and `cargo test --workspace` (745 tests) pass; `drygascon` builds on cl.exe through a build-only compat header. Not run: sanitizers, Miri, fuzz, wasm.

### 2026-11-08: P2 batch C (crate rows: PQC, ECC, EdDSA, X448)
- **Imported (31 new ids, registry now 279 algorithms):**
  - ML-KEM: `ml-kem-512`, `ml-kem-1024`. ML-DSA: `ml-dsa-44` (COSE -48), `ml-dsa-87` (COSE -50). Same crates and key formats as `ml-kem-768` / `ml-dsa-65`.
  - SLH-DSA, all 12 FIPS 205 sets (`slh-dsa-{sha2,shake}-{128,192,256}{s,f}`, crate `slh-dsa` 0.1.0): hedged by default, `deterministic` param, sk = FIPS 205 4n-byte key. No IANA COSE id exists, so root API only.
  - ECDSA `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `ecdsa-secp256k1` (hash fixed per curve, COSE -9 / -51 / -52 / -47; the `det-ecdsa` row is the `deterministic=1` param). ECDH `ecdh-p256`, `ecdh-p384`, `ecdh-p521`. `x448`, `ed448` (COSE -53), `schnorr-bip340`.
- **KATs:** NIST ACVP-Server 975de31e (ML-KEM, ML-DSA, SLH-DSA, ECDSA incl. deterministic replay, EdDSA ED-448), Wycheproof d17cc89f (ECDSA, ECDH, X448, Ed448; full files, accept and reject), RFC 8032 / 7748, official BIP 340 vectors. SLH-DSA uses a deterministic subset (rule in each kat/README.md). URL and sha256 are in every kat/README.md. Wycheproof found that the Ed448 crate ignores the unused bits of R: the glue now rejects them.
- **Pre-release pins:** `x448` 0.14.0-pre.12 and `ed448-goldilocks` 0.14.0-pre.15 (the stable crates named in the CSV either lack signatures or do not zeroize); `slh-dsa` 0.1.0 needs `signature =2.3.0-pre.4`.
- **Blocked (about 40 rows):** RSA (smoke test needs fixed-size public keys; open Marvin advisory), HPKE/ECIES, DSA, recoverable ECDSA, sr25519, SM2, BBS, blind RSA, chacha20-drbg, all PAKEs, ASN.1/CMS codecs, libsignal rows. Reasons in docs/p2/STATUS.md.
- **Owner decisions needed:** sibling ids per RSA modulus size (or a smoke-test change); how to treat the unresolved RUSTSEC-2023-0071 in rsa 0.9.x; an `unverified` import of SM2 and sr25519; a PKE kind for RSA-OAEP/HPKE; a PAKE kind; whether the dev profile should optimize crypto dependencies (SLH-DSA SHAKE sets take 40+ minutes per set in an unoptimized build).
- **Verified by the agent:** see the gate lines at the end of `docs/p2/STATUS.md`. Not run: sanitizers, Miri, fuzz, wasm.

### 2026-11-08: Source collection pass (not wired, not tested)
- `collection/MANIFEST.csv` has 539 rows: 132 collected, 174 crate-pinned, 29 link-only, 204 not found. `collection/` is 146 MB.
- 30 rows have heuristically guessed file selections and need review. 21 rows are copyleft.
- These are raw sources only. They do not count as algorithms until glue and KATs exist. The site must not count them.

- A later search pass damaged and then restored the manifest. Its crate-pinned rows were rebuilt from `docs/p2/sources_*.csv`, so the current counts are in `collection/MANIFEST.csv`.

### 2026-11-08: Composition engine (`nextssl-compose`) and FF70
- **Engine:** new crate `crates/nextssl-compose`. Composition strings `ctor(arg,...)` (strict grammar: 128 bytes, depth 4, lowercase, no whitespace, aliases resolved to canonical, wrong slot kind and unknown ids are explicit errors, no fallback). Constructors: `hmac`, `cmac`, `hkdf`, `pbkdf2(hmac(d))`, `cbc`, `ecb`, `cfb`, `hmac-drbg`, `hash-drbg`, `ctr-drbg` (AES, with and without derivation function), `hashcash`. Crypto stays in the upstream generics (`hmac`, `hkdf`, `pbkdf2`, `cmac`, `cbc`, `ecb`, `cfb-mode`).
- **Slots are generated:** `digest = ".."`, `digests = {..}` (hash) and `cipher = ".."` (block cipher) in `algo.toml`; `cargo xtask gen` emits `crates/nextssl-compose/src/generated.rs` and the crate's dependency and `compose-all` feature blocks. 34 digest names (SHA-2 x6, SHA-3 x4, Keccak x2, MD2/4/5, SHA-1, RIPEMD x4, SM3, Whirlpool, Tiger, Streebog x2, GOST 94, Groestl x4, JH x4) and 16 ciphers (AES x3, ARIA x3, Camellia x3, SM4, Kuznyechik, Magma, Belt, IDEA, DES, 3DES). SHA-2, SHA-3 and AES are always compiled in; the rest need `compose-all` (`Unsupported` otherwise). `slot_version` pins the slot crate separately (sha3 0.12 has no block-level core; HMAC uses 0.11).
- **Effective tier** = worst part (`safe > standard > legacy > research > unverified > broken`, own order, not the enum `Ord`); the safe API refuses below `standard` with `TierNotAllowed`. DRBGs and hashcash are `unverified`, ECB `legacy`, a checksum in the hashcash slot `broken`.
- **API:** `nextssl::compose`, `compose_with`, `random_bytes`, `random_key`, `keygen_with_rng` (safe/standard RNGs only: `os-entropy`, `hmac-drbg-sha256`) and the same in `nextssl_root` (every tier, composed DRBGs such as `hash-drbg(sha256)`). `Pow` trait defined (`sizes`, `difficulty`, `solve(challenge, difficulty, max_work)`, `verify`; new `Error::WorkLimitExceeded`). API.md has the engine, keygen and PoW sections.
- **Hashcash:** v1 stamp over any registered hash, XOF or checksum; verified against the hashcash.org example stamp. Equihash, RandomX, Cuckoo Cycle, Argon2- and scrypt-based PoW were not started.
- **FF70** (`encoding/ff70/ff70`, tier `unverified`): safe-Rust rewrite of the owner's C code, frame `[Header](Config){Data|Sum}[Meta]` kept, BLAKE3 from the pinned crate. All 10 defects of the C original fixed (see `upstream/ORIGIN.md`). Root `ff70_parse` returns header, exclude, meta and payload. Registry now 280 algorithms.
- **Tests:** CAVP DRBG subset (HMAC_DRBG and Hash_DRBG with SHA-1/224/256/512, CTR_DRBG with AES-128/192/256 with and without df; 112 vectors; sets named in `kat/README.md`), equality of `hmac-drbg(sha256)` with the libcrux id, RFC 4231 / 5869 / 7914 / 4493, SP 800-38A CBC, concrete-id equivalence (hmac, hkdf, pbkdf2, cmac, cbc), grammar and tier rules, FF70 KATs (10 from a transcription of the C original, 5 for the fixed cases) and hostile frames. Gate on the host: `cargo xtask gen --check` clean, `cargo fmt --check` clean, clippy `-D warnings` clean (workspace, `compose-all` on and default), tests of core, registry, nextssl, nextssl-root, nextssl-compose (default and `compose-all`), ff70 and xtask all pass.
- **Not run (named):** the compiled FF70 C original in Docker (daemon down, no C compiler on the host), the DRBG differential against OpenSSL, sanitizers, Miri, fuzz, wasm, `check-symbols` (no C added), the full workspace test run.
- **Not type-level selectable (listed):** BLAKE2 and Skein (lazy-buffer cores, `hmac` needs eager), BLAKE3, SHAKE, ParallelHash, BLAKE2bp/sp (not RustCrypto `Digest`), C-backed hashes, and variable-key ciphers (Blowfish, CAST5/6, Serpent, Twofish, Threefish, RC2, RC5). `pbkdf2(hmac(blake2b-512))` from the brief therefore returns `Unsupported`; the concrete BLAKE2 MAC ids cover keyed BLAKE2.
- **Owner decisions needed:** (1) the DRBGs and hashcash are our own Rust state machines written from SP 800-90A (no generic upstream exists), not the C port the port exception names; accept as `unverified` or require a C/Java port plus Docker differential. (2) Whether hashcash should stay `unverified`. (3) Whether `compose-all` should be on by default for the root crate. (4) CTR_DRBG only for AES (3DES/TDEA left out).

## Current mode (owner, 2026-11-08)
Collection first: get every remaining source onto disk under `collection/` (see `docs/p2/BRIEF_collect.md`). Testing, wiring and the composition batch wait for the owner's review. Last verified state: 279 algorithms, 869 tests passed, 0 failed on the Windows host. Upstream bugs we notice go in `docs/UPSTREAM_ISSUES.md`.

## Next (re-planned 2026-11-08 after owner feedback)
1. Group C crates: PQC ML-KEM, ML-DSA and SLH-DSA sets, then ECDSA, ECDH, X448, Ed448 and RSA (running).
2. Composition batch (`docs/p2/BRIEF_compose.md`):
   - every hash is selectable in HMAC, HKDF, PBKDF2 and the DRBGs, with the list generated;
   - HMAC_DRBG, Hash_DRBG and CTR_DRBG over any hash or AES;
   - random keygen with a user-chosen RNG;
   - a PoW kind: Hashcash, Equihash, RandomX, Cuckoo, and Argon2- and scrypt-based PoW.
3. Group C C rows: PQClean, liboqs and authors' C, covering HQC, BIKE, FrodoKEM, McEliece, Falcon, MAYO, SQIsign, HAWK and more.
4. Ports of other-language sources, as `unverified`.
5. The full Docker gate, run once at the end.

### 2026-11-08: Wire batch, KEM and signatures (untested)
- Generated 17 C-backed algorithms from PQClean (HQC-128/192/256, Classic McEliece x10, Falcon-512/1024 and padded), tier `unverified`, registry now 297. Not compiled or tested by owner order; a single fix pass follows. Other KEM/signature families not wired yet (see docs/p2/STATUS.md).
- Wire batch 2 (untested): +6 NTRU sets and +18 CROSS sets (liboqs clean dirs, PQClean fips202), registry 321 after `xtask gen`. Frodo, Saber, MAYO, SPHINCS+, SQIsign, UOV, SDITH, NTRU Prime and NIST-package rows skipped with reasons in docs/p2/STATUS.md.

### 2026-11-08: Wire batch 3, crate-pinned hash/block/stream/encoding rows (untested)
- Generated 3 algorithms from the crate-pinned rows: `base85` (RFC 1924, encoding), `zuc` (ZUC-128 keystream, stream) and `hc256` (HC-256 stream). Tier `unverified`, KAT files present with empty vectors, not compiled or tested (owner order). `cargo xtask gen` ran: 324 algorithms.
- Skipped with reasons in docs/p2/STATUS.md (integer-only base62, PKI encodings, unnamed CRC variants, TupleHash shape, zk field hashes, a wrong `seed` crate pin, multi-key-size block ciphers pending an owner split, NOASSERTION licenses, composition rows).

### 2026-11-08: Wire batch 4, NIST-package and SUPERCOP-layout rows (untested)
- Generated 42 C-backed algorithms from 232 collected rows without a folder (generator D:\Dev\kat_work\wire3\wire3.py): kem 4 (kyber, newhope, ntru-plus, smaug), sign 9 (mayo, hufu, kaz-sign, raccoon, ge-mss, ascon-sign, dme-sign, ehtv3, ncc-sign), hash 3, aead 26, stream 0; 4+9+3+26+0 = 42. Tier `unverified`, 6 GPL-family rows with `copyleft = true`, 40 rows carry an upstream/LICENSE placeholder because the collected tree had no license file. Not compiled or tested (owner order); `cargo xtask gen` ran: 366 algorithms (324 + 42).
- Skipped 190: no uniform api.h entry point 100, C++ 28, unresolved header/external lib 23, port rows 17, arch-only variants 11, unevaluable sizes 5, kind mismatch 3, nsec 1, umbrella 1, own randombytes 1; 100+28+23+17+11+5+3+1+1+1 = 190, and 42 + 190 = 232. Frodo, SPHINCS+, SQIsign and Saber are skipped with reasons in docs/p2/STATUS.md. Upstream rng.c is never compiled; `randombytes` comes from shim.c.

### 2026-11-08: Wire batch 5, crate-pinned aead/kdf/pwhash/sign/kem/kex rows (untested)
- Generated 1 algorithm (generator D:\Dev\kat_work\wire4\wire4.py): sign 1 (sm2-sign), aead 0, kdf 0, pwhash 0, kem 0, kex 0; total 1. Tier `unverified`, empty KAT. Not compiled or tested (owner order); `cargo xtask gen` ran: 367 algorithms (366 + 1).
- Skipped: RSA 12 ids (signature version conflict with slh-dsa pin) + dsa 1 + det/recoverable ecdsa 2 + hkdf-label/tls13 2 + crates not in registry 10 + interactive PAKE 4 + already present 14 + Frodo/SPHINCS+/SQIsign 3 (no generator variant) = 48. Reasons in docs/p2/STATUS.md.

### 2026-11-08: Wire batch 5, hash / AEAD / stream / block / MAC C rows (untested)
- Generated 3 algorithms (generator D:\Dev\kat_work\wire5\wire5.py, reuses wire3 templates): aead 3, stream 0, hash 0, block 0, mac 0; total 3 (lightweight-crypto ace, gimli, orange). Tier `unverified`, empty KAT. Not compiled or tested (owner order); `cargo xtask gen` ran: 370 algorithms ok (367 + 3). Nothing committed.
- Skipped 111 of 114 collected C/C++ rows: already under algos/ 29; block cipher 29 and MAC 1 with no shape template 30; C++ sources (.cpp path not wired) 14; no entry point or prototype not SUPERCOP/LWC shaped 28; several entry points in one row (variant ids need owner decision) 4; needs external lib or missing header 3; secret message number (NSEC) 1; no upstream folder 1; size macro missing 1. Per-row reasons in docs/p2/STATUS.md.
- Deviation from brief: C++ rows were skipped rather than built with cc .cpp(true), and block-cipher and MAC shapes were not written; both need the owner's go-ahead for the next batch.

### 2026-11-08: Wire5 extension, block / C++ / variant rows (untested)
- Generated 19 algorithms (generator D:\Dev\kat_work\wire5\wire5.py --ext): block 9 (libtomcrypt rc6, kasumi, skipjack, xtea, tea, anubis, khazad, noekeon, safer-plus; sizes from the upstream cipher descriptor, shim.c owns the key schedule), C++ 3 (hc128 via Crypto++ shim.cpp, paeq, primates via extern "C" shim.cpp), variants 7 (hyena-v1/v2, oribatida-192/256, saturnin, spoc-128/64); 9+3+7 = 19. Tier `unverified`, empty KAT. Not compiled or tested (owner order); `cargo xtask gen` ran: 389 algorithms ok (370 + 19).
- Skipped 33: block 20 (no upstream folder 5, VARIANTS 2, no headers or class-only header 4, API 5, S-box param 1, C++ class lib 3), MAC 1 (vmac), C++ 11 (shape 5, variants 2, endianness template 2, no API 1, missing brg_endian.h 1), variant 1 (saturnin_short); 20+1+11+1 = 33. Reasons in docs/p2/STATUS.md.
- ace, gimli, orange checked: every quoted include resolves and every .c is present; only AVR/ARM .S files are left out, nothing to copy.

### 2026-11-09: Compile-and-fix pass (host Windows MSVC)
- `cargo check --workspace --keep-going` passes: 349 algorithm folders compiled in algos/, 40 parked in algos_parked/ (MSVC cannot compile 5, missing source or dependency 8, missing crypto_intN library 6, registry smoke failure 21), total 389. No folder deleted.
- `cargo test -p nextssl-registry` passes: 18 passed, 0 failed (14 unit + 4 kat); the smoke test covers all 349 algorithms.
- Layers not run: Docker/Linux builds, ASan/UBSan/MSan, Miri, fuzz, dudect, differential, QEMU, WASM, bindings; per-algorithm KATs of generated folders (empty, still `unverified`); RSA/slh-dsa version conflict left open. Generators fixed: wire/wire.py (BUILD preamble), wire3/wire3.py. Nothing committed.

### 2026-11-09: Parked smoke failures, test entropy fix
- Root cause of the 21 smoke failures (mceliece hang, ntru assertion, dme-sign hang) was the registry smoke test's constant FixedEntropy; it now uses a deterministic non-constant splitmix64 stream (capped 256 MiB), runs each algorithm on a 64 MiB-stack thread with a 300 s timeout and lists every failure. Restored to algos/: mceliece 10, ntru 6, dme-sign 1 = 17 (dme-sign glue got a `MSG_FIRST` layout const).
- Still parked (smoke): jambu, minalpher, paeq, primates = 4 (seal/open failures, jambu also heap corruption); total parked 23 (5 MSVC + 8 source + 6 crypto_intN + 4 smoke). algos/ = 366 (`cargo xtask gen`: 366 algorithms ok). `cargo test -p nextssl-registry`: 18 passed, 0 failed. McEliece needs about 2 MiB stack (pk_gen.c mat array). Docker/sanitizer/Miri/fuzz layers not run. Generators: wire3 PARKED updated, wire5 locate() and wire.py now guard parked ids. Nothing committed.
