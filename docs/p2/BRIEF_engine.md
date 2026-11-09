# Composition engine brief (sonnet). Replaces section 1 of BRIEF_compose.md; sections 2-4 still apply as trimmed here.

Owner decision: composite algorithms are not imported one by one. One engine builds them from parts:
a constructor (processor) plus one or more slots (source algorithms).

Read first: CLAUDE.md, crates/nextssl-core/API.md, algos/mac/hmac/hmac, xtask/src/rootgen.rs.
Cost rule: no interim builds. At the end run only `cargo xtask gen --check`, clippy `-D warnings`, and tests of the
crates you touched. Report under 25 lines. Do not commit.

## Engine
- Canonical name grammar: `ctor(arg[,arg...])`, nested, e.g. `hmac(sha3-256)`, `pbkdf2(hmac(blake2b-512))`, `hkdf(sm3)`,
  `hmac-drbg(sha512)`, `hash-drbg(sha256)`, `ctr-drbg(aes-256)`, `cmac(aria-256)`, `cbc(camellia-128)`, `hashcash(sha256)`.
- Parser is strict Rust: max length 128, max depth 4, no whitespace, lowercase, every id must resolve, wrong slot kind is
  an explicit error. Aliases resolve to the canonical form. No fallback.
- Existing concrete ids stay and resolve to the same output (hmac-sha256 == hmac(sha256)); add a test for a few.
- Crypto stays in upstream generics. Two slot classes:
  - `digest` / `cipher`: type-level. A hash or block `algo.toml` declares `digest = "sha2::Sha256"` or
    `cipher = "aes::Aes256"`; gen emits the dispatch macros, so a new algorithm is selectable automatically. Fill these fields
    for all crate-backed hashes and block ciphers where the type meets the upstream's trait bounds; list those that do not.
  - `oneshot`: dynamic through the registry (`&dyn Hash` / Xof), so C-backed hashes work too. Used by Hashcash and seed
    expansion. Checksums are allowed in `oneshot` slots through root only, with effective tier broken.
- Effective tier = worst part, order safe > standard > legacy > research > unverified > broken. Do not use the enum's
  derived Ord. Safe API refuses anything below standard with `TierNotAllowed`.
- Scope limit: compositions are MAC, KDF, PwHash, DRBG, BlockMode, PoW. No composed AEAD in the safe envelope:
  compositions have no COSE id, so they are root and direct API only.
- Binary size: put the generated dispatch behind a cargo feature `compose-all`, with a small default set (SHA-2, SHA-3,
  BLAKE2, AES). Selecting a part that is not compiled in returns an explicit error.
- Root accessor: `nextssl_root::compose("hmac(sm3)")` returning an instance handle with the kind's operations.

## On the engine (trimmed)
- HMAC, HKDF, PBKDF2, CMAC, CBC/ECB/CFB, HMAC_DRBG, Hash_DRBG, CTR_DRBG as constructors. DRBG upstream rules are in
  BRIEF_compose.md section 2. KAT: a small subset of NIST CAVP drbgtestvectors for two hashes each.
- Random keygen: BRIEF_compose.md section 3.
- PoW trait and Hashcash only: BRIEF_compose.md section 4. Equihash, RandomX, Cuckoo wait.

## FF70 (owner's own encoding, reference in collection/encoding/ff70/ff70/upstream/)
Rewrite in safe Rust at algos/encoding/ff70/ff70, tier `unverified`, license as the repo, BLAKE3 from the pinned crate.
Keep the frame `[Header](Config){Data|Sum}[Meta]`. Params: header, exclude, meta (str, default empty). Add a root
function returning the parsed frame. Fix these defects in the C original (all verified by reading it):
1. Base can reach 0 or 1 through `exclude`: division by zero or endless loop. Require base >= 2 (recommend >= 16).
2. encode buffer `bin_len*2+16` overflows the heap for small bases.
3. Empty input leaves enc_data uninitialized and prints it. Define empty payload as an empty Data field.
4. All-zero input emits one symbol too many, so decode returns one extra byte and its own output fails.
5. Header/config/meta are silently truncated on decode and config on encode. Return an error instead (rule 5).
6. Header/meta containing `]`, or exclude containing `(`-frame characters, break framing. Reject.
7. Trailing data and an unterminated meta are silently accepted. Reject.
8. Decode is quadratic on attacker input. Cap the input length.
9. Exclude must be canonical (sorted, unique, inside the alphabet) so one payload has one encoding.
10. The 4-byte checksum is an error check only. Say so in docs; it gives no integrity against an attacker.
`|` is in the alphabet but always excluded, so the real base is 69: keep that for compatibility.
Differential KAT: build the C original in Docker with official BLAKE3 for inputs free of the defects above, store outputs.
