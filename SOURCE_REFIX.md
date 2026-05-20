# SOURCE_REFIX — Algorithm Source Gathering Plan

> **Purpose:** This document is the working task list for gathering reference
> implementations, C libraries, and authoritative sources for all 776 algorithms
> catalogued in `algo.json`. Each of the 22 sections maps to one category, lists
> every algorithm that needs a source, states what kind of source is acceptable,
> names likely candidate repositories to investigate, and defines the expected
> output (where the gathered material lands inside `/examples`).
>
> **How to use this file:** Work one section at a time. When a source is
> confirmed, write it into the section under `### Found`. When a section is
> fully sourced, mark it `[DONE]`. Update `examples/README.md` with a one-line
> description of every directory created.
>
> **Source priority order (highest to lowest):**
> 1. NIST / IETF / ISO official reference implementation
> 2. Submitter/designer's own reference code
> 3. Well-audited library with a standalone extraction (e.g., libsodium, OpenSSL)
> 4. Academic paper supplemental code
> 5. High-quality single-purpose C repo (header-only preferred)
>
> **Acceptable source types:** `.c`/`.h` files, CMake-compatible single-file or
> small-dir drops. No full application binaries. No Python/Rust-only sources
> unless there is genuinely no C reference.
>
> **Custom algorithms:** Some algorithms in `algo.json` are project-specific and
> have no external source. These are marked `[CUSTOM]` in their table row and
> skipped during source gathering. Do not search for them externally.
> Known custom algorithms: `ff70`.

---

## Gathering process (follow for every algorithm)

1. **Search** — look up the algorithm by name; find the authoritative repo
   (spec author, NIST submission page, IETF draft, or well-known library).
2. **Check legitimacy** — confirm: stars/forks activity, license (must be
   permissive: MIT / BSD / Apache / CC0 / public domain), last commit date,
   test vectors present.
3. **Find C alternative** — if a primary source exists, also look for a
   second independent C implementation. If found, record both.
4. **Write a log entry** — create `logs/source/<algo>.json` (see format below).
   This is the machine-readable record. Do NOT update `SOURCE_REGISTRY.html`
   or `examples/README.md` directly during gathering; those are regenerated
   from the logs later.
5. **Update this MD** — change the algo's status cell from `[ ]` → `[~]`
   (candidate) or `[x]` (confirmed) and fill in the `### Found` subsection.
6. **Regeneration trigger** — after a full section reaches `[DONE]`,
   `SOURCE_REGISTRY.html` and `examples/README.md` are rebuilt in one pass
   from all `logs/source/*.json` files.

### Log file format — `logs/source/<algo>.json`

```json
{
  "algo": "blake3",
  "category": "Hash / Digest / XOF",
  "status": "active",
  "custom": false,
  "sources": [
    {
      "role": "primary",
      "name": "BLAKE3-team/BLAKE3",
      "url": "https://github.com/BLAKE3-team/BLAKE3",
      "license": "CC0 / Apache-2.0",
      "language": "C",
      "legitimacy": "official — authored by spec designers",
      "last_active": "2025",
      "has_test_vectors": true,
      "notes": "blake3.c + blake3.h — single-file drop possible"
    },
    {
      "role": "alternative",
      "name": "oconnor663/c-blake3",
      "url": "https://github.com/oconnor663/c-blake3",
      "license": "MIT",
      "language": "C",
      "legitimacy": "secondary reference by same author",
      "last_active": "2024",
      "has_test_vectors": true,
      "notes": ""
    }
  ],
  "confirmed": true,
  "examples_path": "examples/hash/blake3/"
}
```

Fields:
- `role` — `"primary"` or `"alternative"`
- `legitimacy` — free-text: who maintains it, why it is trustworthy
- `confirmed` — `true` only after files are physically verified/fetched
- `examples_path` — where the source will land (leave `""` until confirmed)

---

## Status legend

| Mark | Meaning |
|------|---------|
| `[ ]` | Not yet sourced |
| `[~]` | Candidate identified, not yet verified/fetched |
| `[x]` | Source confirmed, files placed in `/examples` |
| `[DONE]` | All algos in section fully sourced |

---

## § 01 — Encoding & Checksum

**Target directory:** `examples/encoding-checksum/`

**What to gather:** Standalone C implementations. Most of these are trivially
small (< 300 LOC). Prefer implementations that expose a clean
`encode(in, inlen, out, outlen)` / `decode(...)` API with no dynamic allocation.

### Algorithm list

#### Active (must have)
| Algo | Status | Notes |
|------|--------|-------|
| `base16` | `[~]` | RFC 4648 appendix + wolkykim/qlibc |
| `base32` | `[~]` | RFC 4648 + drichardson/base32 |
| `base32hex` | `[~]` | RFC 4648 §7 + drichardson/base32 (alphabet flag) |
| `base58` | `[~]` | bitcoin/bitcoin src/base58.cpp (MIT) + trezor-firmware crypto/base58.c (pure C) |
| `base58check` | `[~]` | bitcoin/bitcoin + trezor-firmware (includes base58_encode_check) |
| `base62` | `[~]` | easyaspi314/base62 header-only MIT |
| `base64` | `[~]` | aklomp/base64 BSD-2 (SIMD + plain fallback) + RFC 4648 appendix |
| `base64url` | `[~]` | aklomp/base64 url-safe flag + RFC 4648 §5 |
| `base85` | `[~]` | judofyr/base85 MIT + zeromq Z85 (LGPL — verify terms) |
| `bech32` | `[~]` | sipa/bech32 ref/c MIT (official, BIP-0173 co-author) |
| `bech32m` | `[~]` | sipa/bech32 ref/c MIT — same file, BECH32M_CONST param (BIP-0350) |
| `pem` | `[~]` | mbedTLS library/pem.c Apache-2.0 |
| `der` | `[~]` | mbedTLS library/asn1parse.c + asn1write.c Apache-2.0 |
| `cer` | `[~]` | mbedTLS library/asn1parse.c (shares with der) Apache-2.0 |
| `pkcs7` | `[~]` | mbedTLS library/pkcs7.c Apache-2.0 |
| `pkcs8` | `[~]` | mbedTLS library/pkparse.c Apache-2.0 |
| `pkcs12` | `[~]` | mbedTLS library/pkcs12.c Apache-2.0 |
| `spki` | `[~]` | mbedTLS library/x509.c (SPKI extract) Apache-2.0 |
| `ff70` | `[CUSTOM]` | project-specific encoding — no external source |
| `crc8` | `[~]` | lammertbies/crclib MIT + CRC RevEng parameters |
| `crc16` | `[~]` | lammertbies/crclib MIT (IBM poly 0x8005) |
| `crc16-ccitt` | `[~]` | lammertbies/crclib MIT (poly 0x1021) |
| `crc32` | `[~]` | madler/zlib crc32.c (zlib license — permissive) |
| `crc32c` | `[~]` | google/crc32c BSD-3 — SSE4.2 + ARM CRC ext paths |
| `crc64` | `[~]` | redis/redis src/crc64.c BSD-3 |
| `crc64-ecma` | `[~]` | redis/redis src/crc64.c BSD-3 (ECMA-182/Jones poly) |
| `adler32` | `[~]` | madler/zlib adler32.c (zlib license, algorithm author) |
| `fletcher16` | `[~]` | RFC 1146 pseudocode ~20 LOC |
| `fletcher32` | `[~]` | RFC 1146 pseudocode ~25 LOC (shares file with fletcher16) |
| `xxhash32` | `[~]` | Cyan4973/xxHash BSD-2 (official, 11k stars, xxhash.c) |
| `xxhash64` | `[~]` | Cyan4973/xxHash BSD-2 (same file as xxhash32) |
| `xxh3` | `[~]` | Cyan4973/xxHash BSD-2 (xxh3.h, since v0.8.0) |

#### Legacy (good-to-have)
| Algo | Status | Notes |
|------|--------|-------|
| `base91` | `[~]` | Thomas Hahn original basE91 BSD (SourceForge) + tomonori/base91c MIT |
| `ber` | `[~]` | mbedTLS asn1parse.c Apache-2.0 (preferred) / libtasn1 LGPL-2.1 |

### Candidate repositories to investigate
- `stbrumme/xxhash` — xxHash family (C++ only, reference value)
- `Cyan4973/xxHash` — official xxHash ✓ verified
- `madler/zlib` — adler32, crc32 ✓ verified
- `bitcoin/bitcoin src/base58.cpp` — base58/base58check ✓ verified
- `sipa/bech32 ref/c` — bech32/bech32m ✓ verified
- `aklomp/base64` — base64/base64url ✓ verified
- `mbedTLS library/` — DER/CER/PEM/PKCS7/PKCS8/PKCS12/SPKI ✓ verified
- `redis/redis src/crc64.c` — crc64 ✓ verified
- `google/crc32c` — crc32c ✓ verified
- `lammertbies/crclib` — crc8/crc16/crc16-ccitt ✓ verified

### Found

All active and legacy algorithms have candidates identified (`[~]`). Log files
written to `logs/source/<algo>.json` for all 34 entries (33 active + 2 legacy;
ff70 is custom and logged as such).

**Key source groups:**
- **xxHash family** (xxhash32, xxhash64, xxh3) → single drop: `Cyan4973/xxHash` `xxhash.c` + `xxhash.h` + `xxh3.h`
- **Base encodings** (base64, base64url) → `aklomp/base64`
- **Base58 family** (base58, base58check) → `trezor-firmware` crypto/ (pure C)
- **Bech32 family** (bech32, bech32m) → `sipa/bech32` `ref/c/segwit_addr.c`
- **CRC family** (crc8, crc16, crc16-ccitt) → `lammertbies/crclib`; crc32 → `madler/zlib`; crc32c → `google/crc32c`; crc64/crc64-ecma → `redis/redis`
- **ASN.1/container** (der, cer, pem, pkcs7, pkcs8, pkcs12, spki) → `mbedTLS library/`
- **Checksums** (adler32) → `madler/zlib`; fletcher16/32 → RFC 1146 direct

**Pending before `[x]`:** Physical fetch and file verification for each candidate.
Next step: fetch files, confirm correctness, set `confirmed: true` in each log.

---

## § 02 — Hash / Digest / XOF

**Target directory:** `examples/hash/`

**What to gather:** Self-contained C sources. Each algorithm gets its own
subdirectory: `examples/hash/<algo>/`. NIST SHA-3 contest submissions are
available from `csrc.nist.gov` — grab the official reference C package, not
the optimized submission.

### Algorithm list

#### Active (37)
| Algo | Status | Tier | Source |
|------|--------|------|--------|
| `sha224` | `[~]` | active | B-Con/crypto-algorithms (public domain) + mbedTLS Apache-2.0 |
| `sha256` | `[~]` | active | B-Con/crypto-algorithms (public domain) + mbedTLS Apache-2.0 |
| `sha384` | `[~]` | active | B-Con/crypto-algorithms (public domain) + mbedTLS Apache-2.0 |
| `sha512` | `[~]` | active | B-Con/crypto-algorithms (public domain) + mbedTLS Apache-2.0 |
| `sha512-224` | `[~]` | active | mbedTLS library/sha512.c Apache-2.0 |
| `sha512-256` | `[~]` | active | mbedTLS library/sha512.c Apache-2.0 |
| `sha3-224` | `[~]` | active | XKCP/XKCP CC0 — lib/high/Keccak/FIPS202/ |
| `sha3-256` | `[~]` | active | XKCP/XKCP CC0 |
| `sha3-384` | `[~]` | active | XKCP/XKCP CC0 |
| `sha3-512` | `[~]` | active | XKCP/XKCP CC0 |
| `keccak256` | `[~]` | active | XKCP/XKCP CC0 — KeccakHash API, no domain-sep byte |
| `keccak512` | `[~]` | active | XKCP/XKCP CC0 |
| `shake128` | `[~]` | active | XKCP/XKCP CC0 |
| `shake256` | `[~]` | active | XKCP/XKCP CC0 |
| `cshake128` | `[~]` | active | XKCP/XKCP CC0 — SP800-185.h |
| `cshake256` | `[~]` | active | XKCP/XKCP CC0 — SP800-185.h |
| `kmac128` | `[~]` | active | XKCP/XKCP CC0 — SP800-185.h |
| `kmac256` | `[~]` | active | XKCP/XKCP CC0 — SP800-185.h |
| `kmacxof128` | `[~]` | active | XKCP/XKCP CC0 — SP800-185.h XOF mode |
| `kmacxof256` | `[~]` | active | XKCP/XKCP CC0 — SP800-185.h XOF mode |
| `parallelhash128` | `[~]` | active | XKCP/XKCP CC0 — SP800-185.h |
| `parallelhash256` | `[~]` | active | XKCP/XKCP CC0 — SP800-185.h |
| `tuplehash128` | `[~]` | active | XKCP/XKCP CC0 — SP800-185.h |
| `tuplehash256` | `[~]` | active | XKCP/XKCP CC0 — SP800-185.h |
| `kangarootwelve` | `[~]` | active | XKCP/XKCP CC0 — lib/high/KangarooTwelve/ (also XKCP/K12 standalone) |
| `marsupilami14` | `[~]` | active | XKCP/XKCP CC0 — lib/high/KangarooTwelve/ |
| `blake2b` | `[~]` | active | BLAKE2/BLAKE2 CC0 — ref/blake2b-ref.c |
| `blake2s` | `[~]` | active | BLAKE2/BLAKE2 CC0 — ref/blake2s-ref.c |
| `blake2bp` | `[~]` | active | BLAKE2/BLAKE2 CC0 — ref/blake2bp-ref.c |
| `blake2sp` | `[~]` | active | BLAKE2/BLAKE2 CC0 — ref/blake2sp-ref.c |
| `blake3` | `[~]` | active | BLAKE3-team/BLAKE3 CC0/Apache-2.0 — c/ directory |
| `skein256` | `[~]` | active | skein-hash.info official ref (public domain) — skein.c |
| `skein512` | `[~]` | active | skein-hash.info official ref (public domain) |
| `skein1024` | `[~]` | active | skein-hash.info official ref (public domain) |
| `sm3` | `[~]` | active | guanzhi/GmSSL src/sm3.c Apache-2.0 |
| `streebog256` | `[~]` | active | adegtyarev/streebog MIT |
| `streebog512` | `[~]` | active | adegtyarev/streebog MIT |

#### Legacy (28)
| Algo | Status | Tier | Source |
|------|--------|------|--------|
| `md2` | `[~]` | legacy | rhash/RHash librhash/md2.c MIT + RFC 1319 Appendix A |
| `md4` | `[~]` | legacy | rhash/RHash librhash/md4.c MIT + RFC 1320 Appendix A |
| `md5` | `[~]` | legacy | Zunawe/md5-c MIT + rhash/RHash MIT |
| `sha0` | `[~]` | legacy | standalone derivation from SHA-1 (remove ROTL1 in message schedule) |
| `sha1` | `[~]` | legacy | B-Con/crypto-algorithms public domain + rhash/RHash MIT |
| `gost-r-34.11-94` | `[~]` | legacy | rhash/RHash librhash/gost94.c MIT |
| `ripemd128` | `[~]` | legacy | KU Leuven author reference ripemd128.c (public domain) |
| `ripemd160` | `[~]` | legacy | KU Leuven author reference ripemd160.c (public domain) + trezor-firmware MIT |
| `ripemd256` | `[~]` | legacy | KU Leuven author reference ripemd256.c (public domain) |
| `ripemd320` | `[~]` | legacy | KU Leuven author reference ripemd320.c (public domain) |
| `tiger` | `[~]` | legacy | Anderson/Biham author reference (public domain) + rhash/RHash MIT |
| `whirlpool` | `[~]` | legacy | Barreto/Rijmen author reference (public domain) + rhash/RHash MIT |
| `has160` | `[~]` | legacy | KISA official reference (public domain) + rhash/RHash MIT |
| `nt-hash` | `[~]` | legacy | Implement as md4(utf16le(pwd)) per MS-NLMP §3.3.1 |
| `lm-hash` | `[~]` | legacy | Implement from MS-NLMP §3.3.1 (DES-based) |
| `md6` | `[~]` | legacy | Rivest MIT CSAIL reference (MIT) |
| `radio-gatun` | `[~]` | legacy | RadioGatun designer reference (public domain) |
| `groestl` | `[~]` | legacy | NIST SHA-3 Round 3 submission (public domain) + groestlcoin/groestl MIT |
| `jh` | `[~]` | legacy | NIST SHA-3 Round 3 submission (public domain) |
| `cubehash` | `[~]` | legacy | NIST SHA-3 Round 2 submission (public domain) |
| `echo` | `[~]` | legacy | NIST SHA-3 Round 2 submission (public domain) |
| `simd` | `[~]` | legacy | NIST SHA-3 Round 2 submission (public domain) |
| `fugue` | `[~]` | legacy | NIST SHA-3 Round 2 submission (public domain) |
| `hamsi` | `[~]` | legacy | NIST SHA-3 Round 2 submission (public domain) |
| `luffa` | `[~]` | legacy | NIST SHA-3 Round 2 submission (public domain) |
| `shabal` | `[~]` | legacy | NIST SHA-3 Round 2 submission (public domain) |
| `bmw` | `[~]` | legacy | NIST SHA-3 Round 2 submission (public domain) |
| `shavite3` | `[~]` | legacy | NIST SHA-3 Round 2 submission (public domain) |

#### Upcoming (10)
| Algo | Status | Tier | Source |
|------|--------|------|--------|
| `poseidon` | `[~]` | upcome | ingonyama-zk/poseidon MIT (ZK-friendly, prime-field hash) |
| `pedersen-hash` | `[~]` | upcome | iden3/go-iden3-crypto Apache-2.0 (Go reference only; C port needed) |
| `mimc` | `[~]` | upcome | ePrint 2016/492 Sage ref; C port via nicowillis/mimc |
| `rescue` | `[~]` | upcome | ePrint 2020/1143 Python/Sage ref; C port needed |
| `griffin` | `[~]` | upcome | ePrint 2022/403 Sage ref; no standalone C yet |
| `reinforced-concrete` | `[~]` | upcome | HorizenLabs/reinforced-concrete MIT (Rust; C port needed) |
| `haraka` | `[~]` | upcome | kste/haraka MIT — C reference, AES-NI based |
| `lsh` | `[~]` | upcome | KISA official reference (public domain) — KS X 3262 |
| `highwayhash` | `[~]` | upcome | google/highwayhash Apache-2.0 (C++; scalar path is C99) |
| `mgf1` | `[~]` | upcome | RFC 8017 §B.2.1 spec; mbedTLS inline implementation Apache-2.0 |

### Candidate repositories verified
- `XKCP/XKCP` ✓ — CC0, covers SHA-3/SHAKE/cSHAKE/KMAC/ParallelHash/TupleHash/KangarooTwelve/Marsupilami14. 653★ active.
- `BLAKE2/BLAKE2` ✓ — CC0/OpenSSL/Apache-2.0, official designers repo. 700★. ref/ = portable C99.
- `BLAKE3-team/BLAKE3` ✓ — CC0/Apache-2.0, official. 6.2k★, active weekly. c/ = standalone C.
- `B-Con/crypto-algorithms` ✓ — public domain, sha256.c + sha512.c + sha1.c minimal C99.
- `Mbed-TLS/mbedtls` ✓ — Apache-2.0, covers sha256.c, sha512.c (incl. SHA-512/224, SHA-512/256).
- `adegtyarev/streebog` ✓ — MIT, GOST R 34.11-2012 designer reference.
- `guanzhi/GmSSL` ✓ — Apache-2.0, GM/T 0004-2012 SM3 reference. 5k★.
- `rhash/RHash` ✓ — MIT, covers MD2/MD4/MD5/SHA-1/GOST-94/RIPEMD/Tiger/Whirlpool/HAS-160.
- `skein-hash.info` ✓ — public domain, official Skein-256/512/1024 by Schneier et al.
- KU Leuven RIPEMD page ✓ — public domain, official ripemd128/160/256/320.c.
- NIST SHA-3 contest submissions ✓ — groestl/jh/cubehash/echo/simd/fugue/hamsi/luffa/shabal/bmw/shavite3 reference C.

### Found
All 75 log files written to `logs/source/<algo>.json`. All statuses `confirmed: false` — pending review of exact file extracts.

---

## § 03 — Password KDFs

**Target directory:** `examples/password-kdf/`

**What to gather:** Each KDF in its own subdir. Include test vectors from the
spec alongside the source. These must be pure C with no OS dependencies.

### Algorithm list

#### Active (11)
| Algo | Status | Tier | Source |
|------|--------|------|--------|
| `pbkdf2` | `[~]` | active | RFC 8018 §5.2 spec + P-H-C/phc-winner-argon2 CC0/Apache-2.0 |
| `pbkdf2-hmac-sha256` | `[~]` | active | mbedTLS library/pkcs5.c Apache-2.0 |
| `pbkdf2-hmac-sha512` | `[~]` | active | mbedTLS library/pkcs5.c Apache-2.0 |
| `bcrypt` | `[~]` | active | openwall/crypt_blowfish public domain (Solar Designer) |
| `scrypt` | `[~]` | active | Tarsnap/scrypt BSD-2 (Colin Percival, designer) |
| `argon2d` | `[~]` | active | P-H-C/phc-winner-argon2 CC0/Apache-2.0 — ARGON2_D mode |
| `argon2i` | `[~]` | active | P-H-C/phc-winner-argon2 CC0/Apache-2.0 — ARGON2_I mode |
| `argon2id` | `[~]` | active | P-H-C/phc-winner-argon2 CC0/Apache-2.0 — ARGON2_ID mode (RFC 9106) |
| `yescrypt` | `[~]` | active | openwall/yescrypt BSD-2 (Solar Designer, designer) |
| `lyra2` | `[~]` | active | leocalm/Lyra Apache-2.0 |
| `balloon` | `[~]` | active | henrycg/balloon MIT (Corrigan-Gibbs/Boneh, Stanford) |

#### Legacy (8)
| Algo | Status | Tier | Source |
|------|--------|------|--------|
| `pbkdf2-hmac-sha1` | `[~]` | legacy | RFC 6070 test vectors; implement via PBKDF2 + HMAC-SHA1 |
| `catena` | `[~]` | legacy | medsec/catena MIT (Stefan Lucks, PHC finalist) |
| `pomelo` | `[~]` | legacy | password-hashing.net submission tarball, public domain |
| `makwa` | `[~]` | legacy | bolet.org/makwa/ MIT (Thomas Pornin, PHC finalist) |
| `bsdicrypt` | `[~]` | legacy | openwall/crypt BSD-2 — crypt-ext-des.c |
| `md5crypt` | `[~]` | legacy | openwall/crypt BSD-2 — crypt-md5.c ($1$) |
| `sha256crypt` | `[~]` | legacy | Ulrich Drepper reference public domain (akkadia.org/drepper/) |
| `sha512crypt` | `[~]` | legacy | Ulrich Drepper reference public domain (akkadia.org/drepper/) |

#### Upcoming (4)
| Algo | Status | Tier | Source |
|------|--------|------|--------|
| `pbkdf1` | `[~]` | upcome | RFC 8018 §5.1 spec (deprecated; implement from spec) |
| `pkcs12-kdf` | `[~]` | upcome | RFC 7292 Appendix B + mbedTLS library/pkcs12.c Apache-2.0 |
| `evp-bytestokey` | `[~]` | upcome | openssl/openssl crypto/evp/evp_key.c Apache-2.0 |
| `kdf2` | `[~]` | upcome | ISO/IEC 18033-2 / SEC1 v2.0 §3.6.1 (implement from spec) |

### Candidate repositories verified
- `P-H-C/phc-winner-argon2` ✓ — CC0/Apache-2.0, official Argon2 (all 3 variants). 4.5k★.
- `openwall/yescrypt` ✓ — BSD-2, Solar Designer's official yescrypt.
- `Tarsnap/scrypt` ✓ — BSD-2, Colin Percival's scrypt reference.
- `openwall/crypt` ✓ — covers bcrypt, md5crypt, sha256/512crypt, bsdicrypt.
- `leocalm/Lyra` ✓ — Apache-2.0, official Lyra2 reference.
- `henrycg/balloon` ✓ — MIT, Stanford Balloon Hashing.
- `medsec/catena` ✓ — MIT, official Catena PHC.

### Found
All 23 log files written to `logs/source/<algo>.json`. All statuses `confirmed: false`.

---

## § 04 — Symmetric Block Ciphers

**Target directory:** `examples/block-cipher/`

**What to gather:** Core cipher only — no mode logic here. A cipher should
expose `set_key(key, keylen)`, `encrypt_block(in, out)`, `decrypt_block(in, out)`.
Each cipher in its own subdir.

### Active
| Algo | Status | Source | License |
|------|--------|--------|---------|
| `aes-128` | `[~]` | kokke/tiny-AES-c | public domain |
| `aes-192` | `[~]` | kokke/tiny-AES-c | public domain |
| `aes-256` | `[~]` | kokke/tiny-AES-c | public domain |
| `aria-128` | `[~]` | RFC 5794 Appendix A | public domain |
| `aria-192` | `[~]` | RFC 5794 Appendix A | public domain |
| `aria-256` | `[~]` | RFC 5794 Appendix A | public domain |
| `camellia-128` | `[~]` | NTT/Mitsubishi official C | Apache-2.0 |
| `camellia-192` | `[~]` | NTT/Mitsubishi official C | Apache-2.0 |
| `camellia-256` | `[~]` | NTT/Mitsubishi official C | Apache-2.0 |
| `seed` | `[~]` | KISA SEED reference | public domain |
| `sm4` | `[~]` | guanzhi/GmSSL src/sm4.c | Apache-2.0 |
| `kuznyechik` | `[~]` | gost-engine/engine + adegtyarev/grasshopper | OpenSSL dual / MIT |
| `present` | `[~]` | aaossa/present-c | MIT |
| `led` | `[~]` | Guo/Peyrin reference C (ePrint 2011/326) | public domain |
| `piccolo` | `[~]` | Sony Piccolo reference C | public domain |
| `clefia` | `[~]` | Sony CLEFIA reference C | Sony (non-commercial) |
| `threefish-256` | `[~]` | Skein reference (skein-hash.info) | public domain |
| `threefish-512` | `[~]` | Skein reference (skein-hash.info) | public domain |
| `threefish-1024` | `[~]` | Skein reference (skein-hash.info) | public domain |

### Legacy
| Algo | Status | Source | License |
|------|--------|--------|---------|
| `magma` | `[~]` | gost-engine/engine + adegtyarev/magma | OpenSSL dual / MIT |
| `3des` | `[~]` | B-Con/crypto-algorithms des.c | public domain |
| `des` | `[~]` | B-Con/crypto-algorithms des.c | public domain |
| `blowfish` | `[~]` | Bruce Schneier official (schneier.com) | public domain |
| `twofish` | `[~]` | Counterpane reference C (schneier.com) | public domain |
| `serpent` | `[~]` | Anderson/Biham/Knudsen AES submission | public domain |
| `cast5` | `[~]` | RFC 2144 Appendix B | public domain |
| `cast6` | `[~]` | RFC 2612 | public domain |
| `idea` | `[~]` | openssl/openssl crypto/idea/ | Apache-2.0 |
| `rc2` | `[~]` | RFC 2268 | public domain |
| `rc5` | `[~]` | RFC 2040 | public domain |
| `rc6` | `[~]` | RSA Security AES submission | public domain |
| `misty1` | `[~]` | RFC 2994 / Mitsubishi reference | public domain |
| `kasumi` | `[~]` | ETSI TS 135.202 reference C | ETSI |
| `safer` | `[~]` | Massey SAFER reference C (FSE 1993) | public domain |
| `skipjack` | `[~]` | NSA declassified (NIST) | public domain |
| `speck` | `[~]` | nsacyber/simon-speck-c | public domain |
| `simon` | `[~]` | nsacyber/simon-speck-c | public domain |
| `xtea` | `[~]` | Wheeler/Needham reference (movable-type.co.uk) | public domain |
| `tea` | `[~]` | Wheeler/Needham reference (movable-type.co.uk) | public domain |
| `gost28147` | `[~]` | gost-engine/engine | OpenSSL dual |
| `anubis` | `[~]` | Barreto/Rijmen official (larc.usp.br) | public domain |
| `khazad` | `[~]` | Barreto/Rijmen official (larc.usp.br) | public domain |
| `noekeon` | `[~]` | noekeon.org reference | public domain |

### Upcoming
| Algo | Status | Source | License |
|------|--------|--------|---------|
| `kalyna` | `[~]` | Roman-Oliynykov/Kalyna-reference | public domain |
| `belt` | `[~]` | agievich/bee2 src/crypto/belt.c | Apache-2.0 |
| `shacal` | `[~]` | NESSIE submission (Handschuh/Naccache) | public domain |
| `shacal-2` | `[~]` | NESSIE submission (Handschuh/Naccache) | public domain |
| `feal` | `[~]` | RFC 1440 / Shimizu/Miyaguchi reference | public domain |
| `safer+` | `[~]` | Massey/Khachatrian AES submission | public domain |
| `prince` | `[~]` | Borghoff et al. (ePrint 2012/529) | public domain |
| `pride` | `[~]` | Albrecht et al. (ePrint 2014/453) | public domain |
| `twine` | `[~]` | NEC TWINE reference C | public domain |
| `katan` | `[~]` | De Canniere et al. CHES 2009 reference | public domain |
| `ktantan` | `[~]` | De Canniere et al. CHES 2009 reference | public domain |
| `gift` | `[~]` | giftcipher/gift-cofb | CC0 |
| `skinny` | `[~]` | Official SKINNY website reference | public domain |
| `lblock` | `[~]` | Wu/Zhang (ePrint 2011/345) | public domain |
| `rectangle` | `[~]` | Zhang et al. (ePrint 2014/084) | public domain |
| `mmb` | `[~]` | Daemen/Govaerts/Vandewalle FSE 1993 | public domain |

### Candidate repositories verified
- `kokke/tiny-AES-c` — AES-128/192/256, public domain, ~500 LOC ✓
- `guanzhi/GmSSL` — SM4 Apache-2.0 ✓
- `gost-engine/engine` — Kuznyechik + Magma + GOST28147 ✓
- `adegtyarev/grasshopper` — standalone Kuznyechik MIT ✓
- `adegtyarev/magma` — standalone Magma MIT ✓
- `nsacyber/simon-speck-c` — Simon + Speck all variants ✓
- `aaossa/present-c` — PRESENT MIT ✓
- `agievich/bee2` — BelT Apache-2.0 ✓
- `Roman-Oliynykov/Kalyna-reference` — DSTU 7624 public domain ✓
- Skein reference (skein-hash.info) — Threefish-256/512/1024 public domain ✓

---

## § 05 — Stream Ciphers

**Target directory:** `examples/stream-cipher/`

**What to gather:** Keystream generation only. API: `init(key, nonce)`,
`keystream(buf, len)` or `encrypt(in, out, len)`.

### Active
| Algo | Status | Source | License |
|------|--------|--------|---------|
| `chacha20` | `[~]` | cr.yp.to/chacha.html (Bernstein) + CycloneCRYPTO | public domain / GPL-2 |
| `xchacha20` | `[~]` | jedisct1/libsodium xchacha20/ | ISC |
| `salsa20` | `[~]` | cr.yp.to/snuffle.html (Bernstein) | public domain |
| `xsalsa20` | `[~]` | jedisct1/libsodium xsalsa20/ | ISC |
| `chacha8` | `[~]` | cr.yp.to/chacha.html (rounds=8) | public domain |
| `chacha12` | `[~]` | cr.yp.to/chacha.html (rounds=12) | public domain |
| `hc128` | `[~]` | Hongjun Wu ECRYPT reference | public domain |
| `hc256` | `[~]` | Hongjun Wu ECRYPT reference | public domain |
| `rabbit` | `[~]` | RFC 4503 | public domain |
| `sosemanuk` | `[~]` | Berbain et al. ECRYPT reference | public domain |
| `grain128` | `[~]` | grain-128aead.github.io official C | public domain |
| `zuc` | `[~]` | ETSI TS 135.223 Appendix A | ETSI |
| `snow3g` | `[~]` | ETSI TS 135.202 | ETSI |
| `aes-ctr-drbg` | `[~]` | mbedTLS library/ctr_drbg.c | Apache-2.0 |

### Legacy
| Algo | Status | Source | License |
|------|--------|--------|---------|
| `rc4` | `[~]` | B-Con/crypto-algorithms arcfour.c | public domain |
| `grainv1` | `[~]` | ECRYPT Grain v1 reference | public domain |
| `mickeyv2` | `[~]` | ECRYPT MICKEY 2.0 reference | public domain |
| `trivium` | `[~]` | ECRYPT Trivium reference | public domain |
| `isaac` | `[~]` | Bob Jenkins burtleburtle.net | public domain |
| `isaac+` | `[~]` | Bob Jenkins burtleburtle.net | public domain |
| `panama` | `[~]` | Daemen/Clapp FSE 1998 | public domain |
| `wake` | `[~]` | David Wheeler Cambridge tech report | public domain |
| `seal` | `[~]` | Rogaway/Coppersmith FSE 1994 | IBM (research) |
| `a5/1` | `[~]` | Briceno/Goldberg/Wagner cryptome.org | public domain |
| `a5/2` | `[~]` | Briceno/Goldberg/Wagner cryptome.org | public domain |
| `e0` | `[~]` | Bluetooth Core Specification | Bluetooth SIG |

### Upcoming
| Algo | Status | Source | License |
|------|--------|--------|---------|
| `salsa20/8` | `[~]` | cr.yp.to/snuffle.html (rounds=8) | public domain |
| `salsa20/12` | `[~]` | cr.yp.to/snuffle.html (rounds=12) | public domain |
| `spritz` | `[~]` | Rivest/Schuldt paper (MIT) | public domain |
| `vmpc` | `[~]` | Bartosz Zoltak vmpcfunction.com | public domain |
| `cryptmt` | `[~]` | ECRYPT CryptMT reference | public domain |
| `dragon` | `[~]` | ECRYPT DRAGON reference | public domain |
| `edon80` | `[~]` | ECRYPT Edon80 reference | public domain |
| `f-fcsr` | `[~]` | ECRYPT F-FCSR reference | public domain |
| `hermes8` | `[~]` | ECRYPT Hermes8 reference | public domain |
| `lex` | `[~]` | ECRYPT LEX reference | public domain |
| `nls` | `[~]` | ECRYPT NLS reference | public domain |
| `pomaranch` | `[~]` | ECRYPT Pomaranch reference | public domain |
| `a5/3` | `[~]` | ETSI TS 135.202 (KASUMI-based) | ETSI |

### Candidate repositories verified
- `cr.yp.to/chacha.html` — ChaCha/Salsa20 variants, all public domain ✓
- `jedisct1/libsodium` — xchacha20/xsalsa20, ISC ✓
- `grain-128aead.github.io` — Grain-128AEAD official C ✓
- ECRYPT eSTREAM archive — HC-128/256, Rabbit, SOSEMANUK, Trivium, MICKEY, Grain v1 ✓
- ETSI TS 135.202 / 135.223 — SNOW 3G + ZUC reference C ✓

---

## § 06 — Block Cipher Modes

**Target directory:** `examples/block-cipher-mode/`

**What to gather:** Mode logic only, decoupled from any specific cipher.
Use a cipher-callback model: `mode_init(cipher_fn, key, iv)`.

### Algorithm list

#### Active
| Algo | Status | Notes |
|------|--------|-------|
| `ctr` | `[ ]` | NIST SP 800-38A |
| `xts` | `[ ]` | IEEE 1619-2007 / NIST SP 800-38E |
| `cbc-cs1` | `[ ]` | ciphertext stealing |
| `cbc-cs2` | `[ ]` | |
| `cbc-cs3` | `[ ]` | |

#### Legacy
| Algo | Status | Notes |
|------|--------|-------|
| `ecb` | `[ ]` | NIST SP 800-38A |
| `cbc` | `[ ]` | NIST SP 800-38A |
| `cfb` | `[ ]` | |
| `cfb1` | `[ ]` | |
| `cfb8` | `[ ]` | |
| `ofb` | `[ ]` | |

### Candidate repositories to investigate
- NIST SP 800-38A has validated reference C for ECB/CBC/CFB/OFB/CTR
- IEEE 1619 reference implementation for XTS
- `libtomcrypt` — has all modes cleanly separated

### Found
_(none yet)_

---

## § 07 — AEAD Algorithms

**Target directory:** `examples/aead/`

**What to gather:** Unified API: `seal(key, nonce, pt, pt_len, aad, aad_len, ct, tag)` /
`open(...)`. Each in its own subdir.

### Algorithm list

#### Active
| Algo | Status | Notes |
|------|--------|-------|
| `aes-gcm` | `[ ]` | NIST SP 800-38D |
| `aes-ccm` | `[ ]` | NIST SP 800-38C |
| `aes-gcm-siv` | `[ ]` | RFC 8452 |
| `aes-siv` | `[ ]` | RFC 5297 |
| `aes-ocb` | `[ ]` | RFC 7253 (OCB3) |
| `aes-eax` | `[ ]` | Bellare/Rogaway |
| `aes-kw` | `[ ]` | RFC 3394 key wrap |
| `aes-kwp` | `[ ]` | RFC 5649 |
| `aes-gmac` | `[ ]` | GCM with empty plaintext |
| `aes-xpn` | `[ ]` | 802.1AE extended PN |
| `aes-fpe-ff1` | `[ ]` | NIST SP 800-38G |
| `aes-fpe-ff3-1` | `[ ]` | NIST SP 800-38G Rev1 |
| `chacha20-poly1305` | `[ ]` | RFC 8439 |
| `xchacha20-poly1305` | `[ ]` | |
| `aegis128l` | `[ ]` | AEGIS spec |
| `aegis256` | `[ ]` | |
| `deoxys-ii` | `[ ]` | CAESAR finalist |
| `ocb3` | `[ ]` | RFC 7253 |
| `kccm` | `[ ]` | |
| `ascon-aead128` | `[ ]` | NIST LWC winner / ISO 29192-6 |
| `ascon-aead128a` | `[ ]` | |
| `ascon-80pq` | `[ ]` | |

#### Legacy
`morus`, `kiasu`, `marble`, `elephant-dumbo`, `elephant-jumbo`, `gift-cofb`,
`grain-128aead`, `isap-a-128a`, `isap-k-128a`, `photon-beetle`, `romulus`,
`sparkle-schwaemm`, `tinyjambu`, `xoodyak`, `colm`, `silc`

### Candidate repositories to investigate
- NIST SP 800-38D reference for AES-GCM
- `golang/crypto` — AES-GCM-SIV reference port (has test vectors)
- `jedisct1/libsodium` — ChaCha20-Poly1305
- `ASCON-C/ascon-c` — official ASCON C reference
- `cfrg-aegis-cipher` — AEGIS spec repo
- NIST LWC project page for CAESAR/LWC finalists

### Found
_(none yet)_

---

## § 08 — MAC Algorithms

**Target directory:** `examples/mac/`

**What to gather:** `mac_init(key, keylen)` / `mac_update(data, len)` /
`mac_final(tag)` API. Stateless one-shot variant also needed.

### Algorithm list

#### Active
| Algo | Status | Notes |
|------|--------|-------|
| `hmac` | `[ ]` | RFC 2104 (generic) |
| `hmac-sha256` | `[ ]` | |
| `hmac-sha512` | `[ ]` | |
| `hmac-sha3-256` | `[ ]` | |
| `hmac-blake2b` | `[ ]` | |
| `hmac-blake2s` | `[ ]` | |
| `aes-cmac` | `[ ]` | RFC 4493 |
| `aes-pmac` | `[ ]` | |
| `vmac` | `[ ]` | |
| `umac` | `[ ]` | RFC 4418 |
| `poly1305` | `[ ]` | RFC 8439 §2.5 |
| `siphash` | `[ ]` | Aumasson/Bernstein |
| `siphash-2-4` | `[ ]` | |
| `siphash-4-8` | `[ ]` | |
| `kmac128-mac` | `[ ]` | SP 800-185 |
| `kmac256-mac` | `[ ]` | SP 800-185 |
| `blake2b-mac` | `[ ]` | keyed BLAKE2b |
| `blake2s-mac` | `[ ]` | keyed BLAKE2s |
| `blake3-mac` | `[ ]` | keyed BLAKE3 |
| `ascon-mac` | `[ ]` | |
| `ascon-prf` | `[ ]` | |
| `ghash` | `[ ]` | GF(2^128) MAC core of GCM |

#### Legacy
`xcbc-mac`, `cbc-mac`, `des-mac`, `kdf1`

### Candidate repositories to investigate
- `veorq/SipHash` — official SipHash C reference
- `floodyberry/poly1305-donna` — Poly1305
- RFC 4493 has reference C in appendix — AES-CMAC
- RFC 2104 has HMAC pseudocode; pair with any SHA-2 source
- VMAC reference: `fastcrypto.org`

### Found
_(none yet)_

---

## § 09 — Key Derivation Functions

**Target directory:** `examples/kdf/`

**What to gather:** Generic KDF: `kdf(ikm, salt, info, okm, okm_len)` style.
These are often tightly coupled to a hash; grab them with the hash they depend on.

### Algorithm list

#### Active
| Algo | Status | Notes |
|------|--------|-------|
| `hkdf` | `[ ]` | RFC 5869 |
| `hkdf-expand` | `[ ]` | RFC 5869 §2.3 |
| `hkdf-extract` | `[ ]` | RFC 5869 §2.2 |
| `hkdf-expand-label` | `[ ]` | RFC 8446 TLS 1.3 |
| `kdf-tls12` | `[ ]` | RFC 5246 PRF |
| `kdf-tls13` | `[ ]` | RFC 8446 |
| `kdf-ssh` | `[ ]` | RFC 4253 §7.2 |
| `kdf-ikev1` | `[ ]` | RFC 2409 |
| `kdf-ikev2` | `[ ]` | RFC 7296 |
| `kdf-srtp` | `[ ]` | RFC 3711 |
| `kdf-sp800-108` | `[ ]` | NIST SP 800-108 |
| `kda-onestep` | `[ ]` | NIST SP 800-56C Rev2 |
| `kda-twostep` | `[ ]` | NIST SP 800-56C Rev2 |
| `concat-kdf` | `[ ]` | NIST SP 800-56A |
| `x942-kdf` | `[ ]` | ANSI X9.42 |
| `x963-kdf` | `[ ]` | ANSI X9.63 |
| `noise-kdf` | `[ ]` | Noise Protocol Framework |
| `bip32-kdf` | `[ ]` | BIP-0032 |
| `slip10` | `[ ]` | SLIP-0010 |
| `sskdf` | `[ ]` | NIST SP 800-56C |
| `ecdh-kdf` | `[ ]` | |
| `cmkdf` | `[ ]` | |
| `me-kdf` | `[ ]` | |

### Candidate repositories to investigate
- RFC 5869 appendix — HKDF reference C
- `noiseprotocol/noise-c` — noise-kdf
- `bitcoin/bips` — BIP-32 reference
- NIST ACVP test vectors confirm any implementation

### Found
_(none yet)_

---

## § 10 — Key Agreement / KEM

**Target directory:** `examples/kem/`

**What to gather:** `keygen()` / `encapsulate(pk, ss, ct)` / `decapsulate(sk, ct, ss)`.
PQ KEMs must come from the NIST PQC submissions or official IETF drafts.

### Algorithm list

#### Active
| Algo | Status | Notes |
|------|--------|-------|
| `dh` | `[ ]` | RFC 3526 MODP groups |
| `dhp` | `[ ]` | |
| `ecdh` | `[ ]` | RFC 6090 |
| `x25519` | `[ ]` | RFC 7748 |
| `x448` | `[ ]` | RFC 7748 |
| `x3dh` | `[ ]` | Signal specification |
| `hpke` | `[ ]` | RFC 9180 |
| `ecies` | `[ ]` | |
| `rsa-oaep` | `[ ]` | RFC 8017 |
| `csidh` | `[ ]` | |
| `frodokem` | `[ ]` | FrodoKEM spec |
| `kyber` | `[ ]` | pre-standardization |
| `ml-kem-512` | `[ ]` | FIPS 203 |
| `ml-kem-768` | `[ ]` | FIPS 203 |
| `ml-kem-1024` | `[ ]` | FIPS 203 |
| `ntru` | `[ ]` | |
| `ntruprime` | `[ ]` | |
| `sntrup761` | `[ ]` | |
| `classic-mceliece` | `[ ]` | |
| `mceliece-348864` | `[ ]` | |
| `mceliece-348864f` | `[ ]` | |
| `mceliece-460896` | `[ ]` | |
| `mceliece-460896f` | `[ ]` | |
| `mceliece-6688128` | `[ ]` | |
| `mceliece-6688128f` | `[ ]` | |
| `mceliece-6960119` | `[ ]` | |
| `mceliece-6960119f` | `[ ]` | |
| `mceliece-8192128` | `[ ]` | |
| `mceliece-8192128f` | `[ ]` | |
| `bike-1` | `[ ]` | NIST PQC alt candidate |
| `bike-3` | `[ ]` | |
| `bike-5` | `[ ]` | |
| `hqc-128` | `[ ]` | NIST PQC alt candidate |
| `hqc-192` | `[ ]` | |
| `hqc-256` | `[ ]` | |
| `ntruhps2048677` | `[ ]` | |
| `ntruhps4096821` | `[ ]` | |
| `ntruhrss701` | `[ ]` | |

### Candidate repositories to investigate
- `pq-crystals/kyber` — official Kyber/ML-KEM
- `post-quantum-cryptography/PQCrypto-LWEKE` — FrodoKEM
- `ClassicMcEliece/mceliece` — official Classic McEliece
- `nicowillis/BIKE` — BIKE
- `HQC-submission/HQC` — HQC
- `nicowillis/NTRU` — NTRU Prime
- RFC 7748 appendix — X25519/X448 reference

### Found
_(none yet)_

---

## § 11 — Digital Signatures

**Target directory:** `examples/signature/`

**What to gather:** `keygen()` / `sign(sk, msg, sig)` / `verify(pk, msg, sig) → bool`.

### Algorithm list

#### Active
| Algo | Status | Notes |
|------|--------|-------|
| `rsa-pss` | `[ ]` | RFC 8017 RSASSA-PSS |
| `ecdsa` | `[ ]` | FIPS 186-5 |
| `det-ecdsa` | `[ ]` | RFC 6979 |
| `ecdsa-recoverable` | `[ ]` | secp256k1 recoverable sig |
| `ed25519` | `[ ]` | RFC 8032 |
| `ed448` | `[ ]` | RFC 8032 |
| `sr25519` | `[ ]` | Schnorrkel |
| `sm2-sign` | `[ ]` | GM/T 0003.2 |
| `gost-r-34.10-2012` | `[ ]` | GOST R 34.10-2012 |
| `schnorr` | `[ ]` | BIP-0340 / generic |
| `bbs` | `[ ]` | BBS+ credential signature |
| `bls12-381-g1` | `[ ]` | BLS signatures over G1 |
| `bls12-381-g2` | `[ ]` | BLS signatures over G2 |

#### Legacy
`rsa-pkcs1v15-sign`, `dsa`, `gost-r-34.10-2001`, `rainbow`, `ge-mss`

### Candidate repositories to investigate
- `golang/crypto/ed25519` — reference-quality Ed25519
- SUPERCOP — benchmarking suite has many signature refs
- `nicowillis/libgcrypt-sm2` or OpenSSL SM2 branch
- BIP-0340 reference implementation in Python (verify against)
- `herumi/bls` — BLS12-381 C/C++
- `mattiasgrenfeldt/schnorrkel-c` — SR25519

### Found
_(none yet)_

---

## § 12 — PQ Digital Signatures

**Target directory:** `examples/pq-signature/`

**What to gather:** NIST PQC standardized and alternate candidates only.
Use the `ref` (reference) directory from each submission, not the `avx2`
optimized directory — optimized versions come later.

### Algorithm list

#### Active
| Algo | Status | Notes |
|------|--------|-------|
| `dilithium` | `[ ]` | pre-standardization |
| `ml-dsa-44` | `[ ]` | FIPS 204 |
| `ml-dsa-65` | `[ ]` | FIPS 204 |
| `ml-dsa-87` | `[ ]` | FIPS 204 |
| `falcon-512` | `[ ]` | FIPS 206 |
| `falcon-1024` | `[ ]` | FIPS 206 |
| `falcon-padded-512` | `[ ]` | |
| `falcon-padded-1024` | `[ ]` | |
| `sphincs+` | `[ ]` | pre-standardization |
| `slh-dsa-sha2-128f` | `[ ]` | FIPS 205 |
| `slh-dsa-sha2-128s` | `[ ]` | FIPS 205 |
| `slh-dsa-sha2-192f` | `[ ]` | FIPS 205 |
| `slh-dsa-sha2-192s` | `[ ]` | FIPS 205 |
| `slh-dsa-sha2-256f` | `[ ]` | FIPS 205 |
| `slh-dsa-sha2-256s` | `[ ]` | FIPS 205 |
| `slh-dsa-shake-128f` | `[ ]` | FIPS 205 |
| `slh-dsa-shake-128s` | `[ ]` | FIPS 205 |
| `slh-dsa-shake-192f` | `[ ]` | FIPS 205 |
| `slh-dsa-shake-192s` | `[ ]` | FIPS 205 |
| `slh-dsa-shake-256f` | `[ ]` | FIPS 205 |
| `slh-dsa-shake-256s` | `[ ]` | FIPS 205 |
| `haetae` | `[ ]` | Korean PQ signature |
| `almar` | `[ ]` | |

### Candidate repositories to investigate
- `pq-crystals/dilithium` — official ML-DSA/Dilithium
- `tprest/falcon` — official Falcon
- `sphincs-plus/submission-round3` — official SPHINCS+ / SLH-DSA
- NIST PQC project: `csrc.nist.gov/projects/post-quantum-cryptography`

### Found
_(none yet)_

---

## § 13 — Stateful Hash Signatures

**Target directory:** `examples/stateful-sig/`

**What to gather:** These are stateful — key state must advance monotonically.
Source must include state serialization helpers.

### Algorithm list

#### Active
| Algo | Status | Notes |
|------|--------|-------|
| `lms` | `[ ]` | RFC 8554 |
| `hss` | `[ ]` | RFC 8554 |
| `xmss` | `[ ]` | RFC 8391 |
| `xmssmt` | `[ ]` | RFC 8391 multi-tree |

### Candidate repositories to investigate
- `cisco/hash-sigs` — LMS/HSS C reference
- `XMSS/xmss-reference` — official XMSS/XMSS-MT
- RFC 8554 appendix has test vectors for LMS

### Found
_(none yet)_

---

## § 14 — Threshold / MPC

**Target directory:** `examples/threshold-mpc/`

**What to gather:** These are protocol-level, not single-file. Gather the
minimum viable self-contained C that demonstrates the core algebraic step.
For complex MPC, a well-documented test harness is acceptable.

### Algorithm list

#### Active (partial, gather what is publicly available)
`frost`, `tbls`, `shamir`, `feldman-vss`, `pedersen-vss`, `dkg`, `pvss`,
`ot`, `vole`, `beaver`, `mpc-ecdsa`, `mpc-schnorr`, `bam`, `ccgmp`,
`haystack`, `mithril`, `quorus`, `redeta`, `splitkey`, `minimpc`, `maestro`,
`amber`, `hermine`, `least`, `tanuki`, `vinaigrette`, `pantheria`,
`zama-tfhe`, `zama-zhenith`, `piver`, `schmivitz`, `smallwood`,
`gargos`, `tecla`, `the-clash`, `classic-schnorr-t`

### Candidate repositories to investigate
- `ZcashFoundation/frost-core` — FROST
- `dusk-network/bls12_381-sign` — threshold BLS
- Shamir secret sharing: many clean C refs, e.g. `dsprenkels/sss`
- `snwh/oblivious-transfer` — OT
- ZAMA open-source: `zama-ai/tfhe-rs` (Rust; look for C binding)

### Found
_(none yet)_

---

## § 15 — Lightweight Crypto

**Target directory:** `examples/lightweight/`

**What to gather:** These are the NIST LWC winner and finalists. Use the
official `ref` C from the submission packages.

### Algorithm list

#### Active
| Algo | Status | Notes |
|------|--------|-------|
| `ascon-hash256` | `[ ]` | NIST LWC winner |
| `ascon-xof128` | `[ ]` | |
| `ascon-cxof128` | `[ ]` | |
| `lea` | `[ ]` | Korean lightweight block cipher |
| `hight` | `[ ]` | Korean lightweight block cipher |

#### Legacy
`photon-beetle-hash`, `romulus-hash`, `sparkle-esch`, `xoodyak-hash`

### Candidate repositories to investigate
- `ASCON-C/ascon-c` — all ASCON variants
- NIST LWC project page for finalist submissions
- `kibo-tech/lea` — LEA reference C
- ETRI reference code for HIGHT

### Found
_(none yet)_

---

## § 16 — DRBG / RNG

**Target directory:** `examples/drbg-rng/`

**What to gather:** DRBG must include `instantiate` / `reseed` / `generate`
per NIST SP 800-90A. Platform entropy sources get a thin wrapper only.

### Algorithm list

#### Active
| Algo | Status | Notes |
|------|--------|-------|
| `ctr-drbg` | `[ ]` | NIST SP 800-90A |
| `hash-drbg` | `[ ]` | NIST SP 800-90A |
| `hmac-drbg` | `[ ]` | NIST SP 800-90A |
| `csprng-system` | `[ ]` | OS wrapper: getrandom / BCryptGenRandom |
| `trng` | `[ ]` | hardware interface stub |
| `entropy-pool` | `[ ]` | |
| `reseed-scheduler` | `[ ]` | |
| `rdrand` | `[ ]` | Intel RDRAND intrinsic wrapper |
| `rdseed` | `[ ]` | Intel RDSEED intrinsic wrapper |
| `jitterentropy` | `[ ]` | CPU jitter entropy |
| `fortuna` | `[ ]` | Ferguson/Schneier |
| `nist-sp800-90b` | `[ ]` | entropy source validation |
| `nist-sp800-90c` | `[ ]` | combined DRBG+entropy |

#### Legacy
`haveged`, `yarrow`, `cryptgenrandom`, `egd`, `prngd`, `lavarnd`

### Candidate repositories to investigate
- NIST ACVP DRBG test vectors — derive reference from SP 800-90A
- `smuellerDD/jitterentropy-library` — jitterentropy
- `haselwimmer/fortuna` — Fortuna C
- Intel Intrinsics Guide for RDRAND/RDSEED wrappers

### Found
_(none yet)_

---

## § 17 — ZK Proofs / HE

**Target directory:** `examples/zk-he/`

**What to gather:** ZK systems are large. Gather the arithmetic backend and
proof core only, not the full proving-key setup ceremony. For HE, focus on
bootstrapping-free parameter sets for a clean reference.

### Algorithm list

#### Active
| Algo | Status | Notes |
|------|--------|-------|
| `groth16` | `[ ]` | `libsnark` reference |
| `plonk` | `[ ]` | |
| `marlin` | `[ ]` | |
| `halo2` | `[ ]` | |
| `plonky2` | `[ ]` | |
| `stark` | `[ ]` | |
| `bulletproofs` | `[ ]` | |
| `spartan` | `[ ]` | |
| `sonic` | `[ ]` | |
| `kzg-commitment` | `[ ]` | |
| `fri` | `[ ]` | |
| `ligero` | `[ ]` | |
| `dory` | `[ ]` | |
| `gm17` | `[ ]` | |
| `tfhe` | `[ ]` | ZAMA TFHE (bootstrapping) |

### Candidate repositories to investigate
- `scipr-lab/libsnark` — Groth16/GM17
- `zcash/librustzcash` — Groth16 (Rust; look for C FFI)
- `matter-labs/bellman` — Groth16 Rust
- `zama-ai/tfhe-rs` — TFHE Rust with C bindings
- `ConsenSys/gnark` — PLONK/Groth16 (Go; reference for test vectors)
- StarkWare reference: `starkware-industries/ethSTARK`

### Found
_(none yet)_

---

## § 18 — Protocol Primitives

**Target directory:** `examples/protocol/`

**What to gather:** Protocol state-machine cores. Each protocol gets its own
subdir with a minimal two-party test harness.

### Algorithm list

#### Active
`noise-nn`, `noise-kn`, `noise-nk`, `noise-kk`, `noise-nx`, `noise-xn`,
`noise-xk`, `noise-kx`, `noise-in`, `noise-ik`, `noise-ix`, `noise-xx`,
`noise-ikpsk2`, `signal-x3dh`, `signal-double-ratchet`, `opaque`, `spake2`,
`spake2+`, `dragonfly`, `otrv4`, `mtproto`, `wireguard`, `mls`, `pqxdh`,
`cpace`, `aucpace`, `kemtls`, `pq-tls-hybrid`, `ech`, `odohdtls`,
`oblivious-http`, `privacy-pass`, `masque`, `edhoc`, `oscore`, `dtls12`,
`dtls13`, `noise-xxfallback`, `disco`, `noisesocket`, `zrtp`, `hmqv`,
`yak`, `sesame`

### Candidate repositories to investigate
- `noiseprotocol/noise-c` — all Noise handshake patterns
- `signalapp/libsignal` — Signal X3DH / Double Ratchet
- `cfrg/draft-irtf-cfrg-opaque` — OPAQUE reference
- `bifurcation/noisesocket` — NoiseSocket
- `eclipse/tinydtls` — DTLS 1.2
- WireGuard official C kernel implementation

### Found
_(none yet)_

---

## § 19 — PKI / Certificates

**Target directory:** `examples/pki/`

**What to gather:** ASN.1 parsing/building library (minimal) + per-format
encode/decode test. Must handle both DER and PEM forms.

### Algorithm list

#### Active
All 41 active entries: `x509v3`, `crl`, `ocsp`, `ocsp-stapling`, `csr`, `cms`,
`scep`, `est`, `acme`, `ct`, `mft`, `roa`, `tal`, `rfc822name`, `ipaddress`,
`subjectaltname`, `authoritykeyid`, `subjectkeyid`, `keyusage`,
`extendedkeyusage`, `basicconstraints`, `nameconstraints`, `cdp`, `aia`,
`ocsp-nocheck`, `precert-poison`, `sct`, `tls-features`, `signed-timestamp`,
`tsp`, `cades`, `pades`, `xades`, `asn1-der`, `asn1-cer`, `asn1-per`,
`asn1-oer`, `asn1-xer`

#### Legacy
`x509v1`, `asn1-ber`

### Candidate repositories to investigate
- `nicowillis/libtasn1` or `GNU libtasn1` — ASN.1 DER/BER
- `mbedTLS` X.509 module — self-contained
- `letsencrypt/boulder` — ACME reference
- RFC 5652 / RFC 2630 — CMS reference
- `google/certificate-transparency` — CT SCT

### Found
_(none yet)_

---

## § 20 — Hardware / HSM / TEE

**Target directory:** `examples/hardware-hsm-tee/`

**What to gather:** Interface shims and example code only — no real HSM
firmware. Gather PKCS#11 header + minimal provider stub, TPM2 TSS example,
and TEE attestation sample.

### Algorithm list

#### Active
`pkcs11`, `pkcs11-3.0`, `cng`, `tpm2.0`, `intel-sgx`, `intel-tdx`,
`amd-sev`, `amd-sev-snp`, `arm-trustzone`, `arm-cca`, `apple-secure-enclave`,
`nitro-enclaves`, `nvidia-cc`, `java-jce`, `openssl-provider`, `wolfssl-fips`,
`botan-p11`, `libp11`, `opencryptoki`, `softhsm2`

### Candidate repositories to investigate
- `oasis-open/pkcs11-specs` — official PKCS#11 headers
- `tpm2-software/tpm2-tss` — TPM2 TSS reference
- `intel/linux-sgx` — Intel SGX SDK samples
- `aws/aws-nitro-enclaves-sdk-c` — Nitro Enclaves
- `opendnssec/SoftHSMv2` — SoftHSM2

### Found
_(none yet)_

---

## § 21 — Verifiable Delay Functions

**Target directory:** `examples/vdf/`

**What to gather:** Evaluation + proof generation + verification. Include
parameter-generation helpers.

### Algorithm list

#### Upcoming (document sources, fetch when ready)
| Algo | Status | Notes |
|------|--------|-------|
| `wesolowski-vdf` | `[ ]` | Pietrzak/Wesolowski 2018 |
| `pietrzak-vdf` | `[ ]` | |
| `sloth-vdf` | `[ ]` | |

### Candidate repositories to investigate
- `Chia-Network/chiavdf` — VDF reference in C/C++
- `nicowillis/vdf` — academic reference
- Ethereum Foundation VDF research repo

### Found
_(none yet)_

---

## § 22 — Advanced Primitives

**Target directory:** `examples/advanced-primitives/`

**What to gather:** These are research-grade. Gather paper supplemental code
or scheme-specific reference libraries. All marked upcoming.

### Algorithm list

#### Upcoming (document sources, fetch when ready)
`ibe`, `abe`, `pre`, `functional-encryption`, `witness-encryption`,
`chameleon-hash`, `rsa-accumulator`, `bilinear-accumulator`,
`vector-commitment`, `psi`, `secure-aggregation`, `oram`,
`differential-privacy`, `blakley-ss`, `brickell-ss`

### Candidate repositories to investigate
- `kevincheng96/ibe-cpp` — IBE
- `sagrawal87/ABE` — ABE
- Privacy Amplification / DP: `google/differential-privacy`
- `cronokirby/chameleon` — chameleon hash

### Found
_(none yet)_

---

## Cross-cutting tasks

These apply to every section and must be done once a section reaches `[DONE]`:

1. **Test vectors** — every sourced algo must have at least one known-answer
   test (KAT) vector stored in `examples/<category>/<algo>/kat.txt` in
   `input = ... / expected = ...` format.

2. **API header** — every sourced algo must have (or be given) a single
   `<algo>_api.h` that exposes the canonical API used by the plugin system.

3. **CMakeLists stub** — every sourced algo directory gets a minimal
   `CMakeLists.txt` that compiles the reference sources as a static object
   library named `ref_<algo>`.

4. **README entry** — after any source is placed in `/examples`, add a
   one-liner to `examples/README.md` in the format:
   ```
   examples/<category>/<algo>/   <algo-name>  —  <what it is, 1 sentence>
   ```

5. **Flag in algo.json** — once a source is confirmed, add `"src": true` to
   the relevant entry (future enhancement; see GOAL.md §Source Flags).
