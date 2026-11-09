# Open items (nothing here may be lost)

Status of every promise and pending decision. Remove a line only when it is really done.

## Work still to do
- Search: SUPERCOP and NIST zip pass (`sources_F.csv`), then collect the new hits and the rows of `sources_E.csv`.
- Re-pin rows lost in the manifest incident: mimc, rescue, reinforced-concrete, spritz, umac, round5, CGGMP.
- Wire collected sources into `algos/` with glue and KATs: 124 collected, 81 crate-pinned.
- New kinds: PKE (RSA-OAEP, HPKE, ECIES), PAKE (SPAKE2, OPAQUE, SRP, CPace), RSA and DSA variable key sizes, TupleHash, CTS/CFB1.
- PoW: Equihash, RandomX, Cuckoo Cycle, Argon2- and scrypt-based PoW.
- Composition gaps: BLAKE2, Skein, BLAKE3, C-backed hashes, variable-key ciphers are not selectable at type level.
- Ports from Java/Go/Python (tier unverified, differential test required): ECMQV, J-PAKE, Grain-128, Grain v1, VMPC, 8 more bc-java rows in `sources_E.csv`, fireblocks CMP.
- P3 families: ZK, threshold, HE, VDF, OPRF, blind signatures. P4 FIPS module. P1b: bindings, signed releases, tinyssl decision.
- Protocol, PKI and platform rows.
- Replace KATs: RIPEMD-128/256/320 were typed from memory; SHA-2 and SHA-3 should use raw NIST CAVP files.
- Mode trait cleanup (old generic `Mode` kind is unused).
- 30 collected rows have guessed file selections ("path guessed" in the manifest).

- Search gaps: 28 of 98 NIST/KpqC zips not fetched; eSTREAM site unreachable; CAESAR packs not found. `sources_F_prefix_hits.txt` holds 51 name-prefix hits, about 5 false (present, twine, whir, jolt); collected on 2026-11-08 (see manifest), license keywords auto-detected and name matches still need review.

## Tests skipped so far (needs Docker running)
Sanitizers, Miri, fuzz, WASM, QEMU, dudect on everything after P1a; full workspace run after the composition engine; DRBG differential vs OpenSSL; FF70 vs the compiled C original; BMW failure under gcc -O2; `--features copyleft` after batch C. CI has never run on GitHub.

## Owner decisions pending
- Hand-written DRBGs and Hashcash: keep as unverified or remove (breaks hard rule 1).
- License no longer blocks copying (owner, archive). RQC license file needs checking. yescrypt BSD assumption.
- RSA: sibling ids per modulus, and the open Marvin advisory in `rsa` 0.9.
- SM2 and sr25519 as unverified. Pre-release pins for x448 and ed448.
- Upstream patch for variable-length Ascon-XOF128; COMET/ESTATE mismatch follow-up.
- crc16-ccitt, crc64 and base85 variants; Keccak tier; `compose-all` default for root.
- HMAC-DRBG zeroize gap and other rule 9 gaps (see `docs/UPSTREAM_ISSUES.md`).
- ML-DSA seed-only private key, KdfCaps defaults, private COSE ids.
- `collection/` (146 MB+) in the repo or manifest only. License: Apache-2.0 + trademark proposal. Whether copyleft ships.
- Commit of everything so far (nothing is committed).
- Site session: start in NextSSL-Web from SITE_PLAN.md.
