# Composition, DRBG, PoW, and random keygen brief (sonnet)

Owner goal: users can switch algorithms freely. A DRBG, KDF, MAC, PoW or keygen must not be stuck on one hash.
Read CLAUDE.md, crates/nextssl-core/API.md, docs/p2/BRIEF_import.md (all rules apply), and how
algos/mac/hmac/hmac and algos/kdf/hkdf/hkdf dispatch over the `hash` enum.

Speed rule: no interim builds. Run the gate once at the end, on the host only: `cargo xtask gen --check`, clippy `-D warnings`, `cargo test --workspace`. Use Docker only for `check-symbols`, and only if C was added.

## 1. Hash selection is generated, not hand-listed
- A hash or XOF `algo.toml` may declare `digest = "<crate path to a RustCrypto Digest type>"`, e.g. `"sha2::Sha256"`.
- `cargo xtask gen` emits a dispatch macro, roughly `with_digest!(id, |D| expr)`, covering every registered hash that has `digest`.
- Composite algorithms (hmac, hkdf, hkdf-extract/expand, pbkdf2, and the new DRBGs) take `hash` as an enum whose values are generated from that list.
- Adding a hash makes it selectable everywhere automatically.
- The upstream generic code (the hmac, hkdf and pbkdf2 crates) still does the crypto; the dispatch is glue only.
- **Tier of a composite:** the minimum of the composite's own tier and the chosen hash's tier, checked at instantiate time.
  - So `hmac` with `hash=md5` is legacy. The safe API refuses it with `TierNotAllowed`; root allows it.
  - Never fall back silently to another hash.
- C-backed hashes have no Digest type. Leave them out of the enum for now and list them in the report.

## 2. DRBGs over any hash or block cipher
- **HMAC_DRBG and Hash_DRBG** (SP 800-90A), generic over the `hash` enum.
- **CTR_DRBG** over AES-128/192/256, with and without the derivation function.
- **Upstream:** find a generic upstream crate (crates.io, RustCrypto, or another widely used crate).
  - If none exists, use a C or other-language reference under the port rules, as tier `unverified`.
- **KATs:** NIST CAVP `drbgtestvectors.zip` covers SHA-1/224/256/384/512/512-224/512-256 and AES for all three DRBGs. Use it with a subset rule.
- **Existing id:** `hmac-drbg-sha256` stays as is, or becomes an alias of `hmac-drbg` with `hash=sha256` if the output is byte-identical.

## 3. Random keygen with user-chosen RNG
- **Safe API and root:**
  - `keygen(alg)`, which already uses OS entropy;
  - `keygen_with_rng(alg, rng)`, where `rng` is `"os-entropy"` or any registered DRBG id plus params. The DRBG is instantiated from OS entropy with a nonce and personalization, then reseeded per SP 800-90A limits.
  - `random_bytes(n, rng)` and `random_key(aead_or_mac_alg, rng)`, which return the correct key length.
- **Safe API rule:** it accepts only safe/standard RNGs.
- **Docs:** state the deterministic (seed) vs random choice in API.md.

## 4. PoW kind
- **Trait:**
  - `Pow { sizes(); solve(challenge, difficulty, params) -> Vec<u8> /*solution*/; verify(challenge, solution, difficulty) -> Result<bool> }`
  - Difficulty is explicit; an out-of-range value is an error.
  - `solve` takes a max-work cap param, so a hostile difficulty cannot hang the caller.
- **Imports**, upstream only, each with published or independent vectors:
  - Hashcash (v1 stamp format, over the `hash` enum, default sha256; the crate or spec reference);
  - Equihash verify (zcash `equihash` crate; solve if the crate offers it);
  - RandomX (tevador/RandomX, C++, BSD-3; light mode, verify-first);
  - Cuckoo Cycle (tromp/cuckoo C, verify);
  - an Argon2id-based and a scrypt-based memory-hard PoW, as compositions over the existing ids.
- **If an upstream fails the 15-file or MSVC rule:** block it with the reason.
- **Docs:** add root accessors (via gen) and an API.md section.

## 5. Report and log
- **Report:** what changed in the API (three usage examples), counts, blocked items, and decisions for the owner.
- **Logs:** append to `docs/PROGRESS.md` and `docs/p2/STATUS.md`.
- **Do not commit.**
