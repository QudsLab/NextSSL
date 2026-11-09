# nextssl-core API cheat-sheet (frozen by P1a)

Read this before writing a `glue.rs`. Source of truth: `src/traits.rs`, `src/keys.rs`, `src/len.rs`.
Import flow: `cargo xtask new <cat>/<family>/<id> --kind <kind> ...` -> fill `algo.toml` (incl. `[sizes]`) ->
replace the `Stub` in `glue.rs` -> add KATs -> `cargo xtask gen`. `new(&Params) -> Result<Box<dyn Trait>>` is the only export.

## Rules every glue follows
- Check every length against your own `sizes()` before use. Wrong length = `Error::InvalidLength` / `BadOutputLen`. Never truncate, pad, ignore a param, or fall back to another algorithm.
- Unsupported feature = `Error::Unsupported`. Context string on an algorithm with `ctx = 0` = error, not ignored.
- Secrets live only in `SymmetricKey` / `PrivateKey` / `SharedSecret` / `Seed` or `Zeroizing<_>` (zeroize on drop, constant-time `==`, redacted `Debug`, no `Clone`). Wipe copies you make. No `Debug`/logging of secrets.
- `sizes()` must declare the fields in `Kind::required_sizes()` and stay **within** `algo.toml [sizes]` (checked by `nextssl_registry::check_sizes`). Variable sizes use `Len::range`. `0` means "none" for `seed`, `coins`, `ctx`, AEAD `nonce`.
- Constant time for anything secret-dependent: compare with `nextssl_core::ct_eq`, never `==` on slices.
- Instances are `Send + Sync` and immutable; only `EntropySource` and `Drbg` are `&mut self` (`Send` only). Interactive kinds keep their state in a separate object (`PakeState`, `ThresholdState`) that is consumed by every step.

## Traits (`kind =` in algo.toml) and required `[sizes]`
| kind | trait | required methods | sizes |
|---|---|---|---|
| hash | `Hash` | `output_len`, `digest(data,out)` | out |
| xof | `Xof` | `squeeze(data,out)` (out non-empty) | - |
| checksum | `Checksum` | `sizes`, `checksum(data,out)` (non-crypto, root only) | out |
| encoding | `Encoding` | `encode`, `decode` (strict) | - |
| mac | `Mac` | `sizes`, `tag(key,data,out)`; `verify` is provided (constant time) | key, tag |
| kdf | `Kdf` | `sizes`, `derive(ikm,salt,info,out)`; optional `extract`/`expand` (HKDF) | out |
| pwhash | `PwHash` | `sizes`, `hash(pw,salt)->PHC`, `verify(pw,phc)`, `derive(pw,salt,out)` | salt, out |
| aead | `Aead` | `sizes`, `seal(key,nonce,aad,pt)->ct\|\|tag`, `open(..)` (`AuthenticationFailed`) | key, nonce, tag |
| blockcipher | `BlockCipher` | `sizes`, `keyed(key)->Box<dyn KeyedBlockCipher>`; `encrypt_block/decrypt_block` provided | key, block |
| streamcipher | `StreamCipher` | `sizes`, `apply_keystream(key,nonce,data)` in place | key, nonce |
| mode | `Mode` | `sizes(cipher)`, `encrypt/decrypt(cipher,key,iv,data)` over any `&dyn BlockCipher` (no algorithm uses it yet; see blockmode) | - |
| blockmode | `BlockMode` | `sizes`, `encrypt(key,nonce,data)`, `decrypt(key,nonce,data)`: a mode with the cipher fixed (`aes-256-cbc`, `aes-128-xts`, `aes-kw`, `aes-fpe-ff1`) | key, nonce |
| kem | `Kem` | `sizes`, `keygen_from_seed`, `encaps_from_coins`, `decaps`; `keygen`/`encaps` provided (draw seed/coins) | pk sk ct ss seed coins |
| kex | `Kex` | `sizes`, `keypair_from_seed`, `agree` (reject low-order/zero) | pk sk ss seed |
| sign | `Sign` | `sizes`, `keygen_from_seed`, `sign(sk,msg,ctx,rng)`, `verify(pk,msg,ctx,sig)` | pk sk sig seed ctx |
| rng | `EntropySource` | `fill(out)` | - |
| drbg | `Drbg` | `sizes`, `security_strength`, `max_request_len`, `instantiate(entropy,nonce,personalization)`, `reseed(entropy,additional)`, `generate(additional,out)`, `uninstantiate` | seed (entropy input) |
| pow | `Pow` | `sizes` (`out` = solution length), `difficulty()` inclusive range, `solve(challenge, difficulty, max_work)` (`WorkLimitExceeded` at the cap), `verify(challenge, solution, difficulty)` (`Ok(false)` = valid form, not enough work) | - |
| pke | `Pke` | `sizes`, `encrypt(pk,pt,label,rng)`, `decrypt(sk,ct,label)` (every failure is `AuthenticationFailed`), optional `keygen(rng)` (RSA-OAEP, PKCS#1 v1.5 enc = tier broken, HPKE, ECIES; root only) | pk sk ct out ctx |
| pake | `Pake`, `PakeState` | `sizes`, `start(role,password,context,rng) -> (state, first msg)`; `PakeState::step(self: Box<Self>, msg) -> PakeStep::{Send(state,msg) \| Done(SharedSecret, Option<msg>)}` (SPAKE2, OPAQUE, SRP, CPace; root only) | key ss |
| statefulsign | `StatefulSign` | `sizes`, `max_signatures`, `remaining(key)`, `keygen(rng)` / `keygen_from_seed`, `sign(&mut StatefulKey, msg, persist)`, `verify` (XMSS, LMS/HSS; root only) | pk sk sig seed |
| zk | `Zk` | `setup(params,rng)`, `prove(setup,statement,witness,rng)`, `verify(setup,statement,proof)` (root only) | - |
| threshold | `Threshold` | `max_parties`, `split(secret,t,n,rng)`, `combine(shares)`, interactive `start(session,rng)` with `ThresholdState::step` (same shape as Pake); `1 <= t <= n <= max_parties` and party ids `1..=n` are enforced (root only) | - |
| he | `He` | `ops()`, `keygen(params,rng) -> HeKeys`, `encrypt`, `decrypt`, `eval(op, cts, evk)`; an op outside `ops()` is `Unsupported` (root only) | - |
| vdf | `Vdf` | `max_t()` (the `max_t` cap param), `eval(challenge,t) -> (output, proof)`, `verify(challenge,t,output,proof)`; `t == 0` or `t > max_t` is `ParamOutOfRange("t")` (root only) | - |

## Conventions
- `Kem`/`Kex`/`Sign` with no deterministic seed (RSA-KEM, McEliece variants...): override `keygen`/`encaps`, return `Unsupported` from `*_from_seed`, set `seed = 0`.
- `verify`: `Ok(false)` = valid encoding, bad signature/tag; `Err` = wrong length or malformed. Callers treat both as reject.
- Randomness always comes from the `&mut dyn EntropySource` argument. KAT runners use `nextssl_core::testing::FixedEntropy` (feature `testing`, dev only).
- Pre-hash / variant modes (Ed25519ph, HashML-DSA, GCM vs GCM-SIV) are separate algorithm ids, not flags. Cost/size knobs are `[params]`, validated before `new` is called.
- PHC strings: id must be this algorithm, cost params must lie inside the schema ranges (no unbounded work from a hostile string), compare hashes with `ct_eq`.
- Block-cipher modes are registered per cipher as concrete algorithms, because the upstream mode crates (`cbc`, `ecb`, `cfb-mode`, `cfb8`, `xts-mode`, `aes-kw`, `fpe`) are generic over a RustCrypto cipher type and cannot run on our `&dyn BlockCipher` without hand-written mode logic (hard rule 1). The right kind per shape: symmetric keystream modes (CTR, OFB) are `streamcipher`; modes with distinct encrypt and decrypt (ECB, CBC, CFB, CFB-8, XTS, key wrap, FPE) are `blockmode`; authenticated compositions (GCM, CCM, OCB, EAX, SIV, GCM-SIV) are `aead`. The generic `Mode` kind stays for a future hand-free implementation and is unused.
- `blockmode`: `nonce` is the IV (CBC, CFB), the tweak (XTS: 16 bytes, FPE: any length) or `0` (ECB, key wrap). Padding is a `[params]` enum (`padding = none | pkcs7`, default `none`: data must then be a block multiple, otherwise an error). Key wrap: encrypt = wrap, decrypt = unwrap; a failed integrity check is `AuthenticationFailed`. FPE: data is one byte per digit, each below the `radix` param. The generic smoke test feeds 32 bytes with values below 10.
- `aead` with `nonce = 0` is a deterministic AEAD (AES-SIV): a non-empty nonce is an error.
- Stream-cipher start counter and similar are `[params]`; refuse inputs that exceed the keystream limit before touching `data`.

- PHC strings: use `nextssl_core::phc` (strict parser/writer, ranges checked before decoding); do not hand-roll one.

## Metadata (`algo.toml`)
`kind`, `tier`, `status`, `standards`, `cose_alg`, `oid`, `fips`, `copyleft` (GPL/LGPL/AGPL upstream: algorithm exists only with cargo feature `copyleft`), `upstream` (one of: `crate` + `version`; `repo` + 40-hex `commit`; or `url` + 64-hex `sha256` for a tarball/zip/single file without a commit; `cargo xtask gen` validates the hex and emits `AlgoInfo::c_backed` = repo or url pin, which the Miri skip in `crates/nextssl-registry/tests/kat.rs` reads), `[params.*]`, `[sizes]` (`key = 32` or `key = { min = 16, max = 32 }`), `[kat]`. Never hand-edit generated files; run `cargo xtask gen`.

## Params: types, enums, required strings
`[params.<name>]` in `algo.toml` takes `type = "u32" | "u64" | "bytes" | "str" | "enum"`.
- `u32`/`u64`/`bytes`/`str`: `min`, `max` (required), optional numeric `default` (u32/u64 only).
- `enum`: `values = [..]` (closed set), optional `default` that must be one of them, no `min`/`max`. At run time it is a `Value::Str`; any other string is `Error::ParamOutOfRange`, never a fallback. In a hand-written `ParamSpec`, use `ParamType::Enum(&[..])` and `default: Some(index)`.
- `required = true` is only for `str` and needs `test_value = ".."` (used by generic tests and by `AlgoInfo::smoke_params()`); a required param has no default, so only the `*_with(params, ..)` root accessors can instantiate it (bech32 `hrp`).

## Sizes used by generic tests
Besides the required fields, an instance may declare `salt` and `info` for a `Kdf` (`0` = the KDF takes none and a non-empty value is an error), and `block` for a `Mac` (message must be a whole number of blocks, non-empty). The registry smoke test derives key, message, salt, info and output lengths from the instance's `sizes()` only.

## Composition engine (`nextssl-compose`)
Composite algorithms are not imported one by one. One engine builds them from a constructor plus slots:
`nextssl_root::compose("pbkdf2(hmac(sm3))")`, `nextssl::compose("hkdf(sha3-512)")`. The result is a `Composed` handle: `canonical()`, `tier()`, `kind()` and the accessors `mac()`, `kdf()`, `pwhash()`, `blockmode()`, `pow()`, `drbg()` (`&mut`) that return `WrongKind` for the other kinds. `compose_with(spec, &Params)` takes parameters.
- **Constructors:** `hmac(d)`, `cmac(c)` (MAC); `hkdf(d)` (KDF); `pbkdf2(hmac(d))` (pwhash, params `iterations`, `out_len`); `cbc(c)`, `ecb(c)`, `cfb(c)` (blockmode, param `padding` for cbc and ecb); `hmac-drbg(d)`, `hash-drbg(d)`, `ctr-drbg(aes-128|aes-192|aes-256)` (param `df` = `yes` or `no`); `hashcash(h)` (pow). `d` = digest slot, `c` = cipher slot, `h` = any registered hash, XOF or checksum.
- **Grammar:** `ctor(arg[,arg...])`, nested; at most 128 bytes, depth 4, 4 arguments; lowercase `a-z 0-9 - _ . ( ) ,`, no whitespace. A registered alias resolves to the canonical name (`canonical()`); a name in the wrong slot is `WrongKind`, a registered algorithm with no type-level slot is `Unsupported`, an unknown one `UnknownAlgorithm`. There is no fallback.
- **Slots:** `digest` and `cipher` are type-level. A hash `algo.toml` declares `digest = "sha2::Sha256"` (or `digests = { "groestl-256" = "groestl::Groestl256" }` for a family with fixed-output variants), a block cipher declares `cipher = "aes::Aes256"`, and `cargo xtask gen` emits the dispatch (`crates/nextssl-compose/src/generated.rs`) and the dependency list. Adding such a field makes the algorithm selectable everywhere. `slot_version = "=x.y.z"` pins another crate version for the slot than for the algorithm itself (sha3 0.12 has no block-level core, HMAC needs 0.11). The crypto stays in the upstream generic crates (`hmac`, `hkdf`, `pbkdf2`, `cmac`, `cbc`, `ecb`, `cfb-mode`). `oneshot` is dynamic through the registry (`hashcash`).
- **Binary size:** SHA-2, SHA-3 and AES are always compiled in; every other slot needs the cargo feature `compose-all` (also on `nextssl` and `nextssl-root`). Without it they return `Unsupported`.
- **Tier:** the worst part wins: `safe > standard > legacy > research > unverified > broken` (not the derived `Ord` of `Tier`). The safe API refuses anything below `standard` with `TierNotAllowed`. `hmac(md5)` is `broken`; `ecb(..)` is `legacy`; the three DRBGs and `hashcash` are `unverified` (our own state machines); a checksum in the `oneshot` slot counts as `broken`.
- **Scope:** MAC, KDF, password hash, block mode, DRBG and PoW only. Compositions have no COSE id, so there is no composed AEAD in the envelope.
- **Not selectable at type level** (use the concrete ids): C-backed hashes, BLAKE2 and Skein (lazy-buffer cores cannot be wrapped by `hmac`), BLAKE3, SHAKE, ParallelHash, and variable-key ciphers (Blowfish, CAST, Serpent, Twofish, Threefish, RC2, RC5).

## Random keygen with a chosen RNG
Deterministic (seed) versus random: the plain `keygen` functions draw from the OS; `*_from_seed` on the traits is the deterministic path. With a chosen RNG:
- `random_bytes(n, rng)` (1..=16 MiB), `random_key(alg, rng)` (AEAD, MAC, stream cipher, block cipher or block mode; a fixed key size gives that size, a range gives `min(max, 64)` but at least the minimum), `keygen_with_rng(alg, rng)` (signature, KEM or KEX).
- `rng` is `"os-entropy"` (or another registered `rng`), a registered DRBG id (`"hmac-drbg-sha256"`), or a composed DRBG (`"hash-drbg(sha512)"`). A DRBG is instantiated from OS entropy (entropy input of its strength, a nonce, personalization `nextssl-rng-v1`) and reseeded from the OS every 2^16 generate calls and on `ReseedRequired` (the SP 800-90A interval is 2^48).
- The safe API (`nextssl::`) accepts only safe and standard RNGs and algorithms, so today only `os-entropy` and `hmac-drbg-sha256`. `nextssl_root::` accepts every tier.

## Proof of work
`hashcash(h)` is the hashcash v1 stamp `1:bits:date:resource:ext:rand:counter`. Challenge = `date:resource:ext:rand` (`date` is 6, 10 or 12 digits), difficulty = leading zero bits (1..=min(64, hash bits)), solution = the counter text. `solve` takes `max_work` and returns `WorkLimitExceeded` when it is reached. Calendar dates are not checked (expiry is for the application). Equihash, RandomX and Cuckoo Cycle wait.

## Root-only kinds (pke, pake, statefulsign, zk, threshold, he, vdf)
`Kind::root_only()` is true for these. The registry refuses them under the safe policy whatever their tier (`TierNotAllowed`), and none has a COSE envelope. `nextssl_root` has string entry points for pke, zk, vdf and threshold (`pke_encrypt`, `zk_prove`, `vdf_eval`, `threshold_split`, plus the generated per-algorithm modules); pake, statefulsign and he are used through `nextssl_registry::new_<kind>_in(.., Policy::Any, ..)` because they carry state or several key objects.
- **Pke:** `ctx` in `[sizes]` is the label length range (`0` = no labels, a non-empty label is an error). Plaintext length range is `out`. Decrypt returns the one uniform `AuthenticationFailed` for bad padding, tag, label or key; a wrong length is `InvalidLength`. The one exception is implicit rejection (RSA PKCS#1 v1.5 in `rsa` 0.10): bad padding returns a deterministic synthetic plaintext, never an error and never the original.
- **Pake:** states are consumed by `step`; a rejected message is an `Err` (use `Error::ProtocolAborted`) and the state is already gone. The first message may be empty (that role waits). For client/server protocols the initiator is the client.
- **StatefulSign:** the glue builds the advanced key state, calls `persist(&new_state)`, and only after `Ok` stores it in the key and releases the signature. A `persist` error is returned as is and no signature is made. An exhausted key is `Error::KeyExhausted` before `persist` is called. `StatefulKey` has no `Clone`.
- **Zk, He, Threshold:** a heavy algorithm may set `smoke = "skip"` and `smoke_reason = "..."` in `algo.toml`; the registry smoke test then names it in the log and does not run the generic round trip. Generic convention for the others: He plaintext is one unsigned byte; Zk is only given `setup(&[])`.
- **Vdf:** the `max_t` cap is a `[params.max_t]` (u64). Never loop longer than the cap.
- Secrets: `StatefulKey`, `Share`, `HeKeys::secret` and Zk witnesses are zeroized on every exit path.
