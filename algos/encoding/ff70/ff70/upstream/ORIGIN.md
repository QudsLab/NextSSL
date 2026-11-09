# ORIGIN: ff70 (FlexFrame-70)

- Source: owner-supplied C reference, `collection/encoding/ff70/ff70/upstream/ff70.c` and `ff70.h`
  (retrieved 2026-11-08; no upstream URL). This crate is a **rewrite in safe Rust**, not a verbatim copy
  (owner decision, docs/p2/BRIEF_engine.md). Tier `unverified`. License: as the repository (Apache-2.0).
- Checksum: BLAKE3 from the pinned `blake3` crate (first 4 bytes of the digest).
- Differential KAT: `kat/vectors.json`, entries `c-original-*` come from a literal Python transcription of
  the C `base_n_encode` / `ff70_encode`; the compiled C original was not run (Docker daemon not running,
  no C compiler on the host). Re-run it in Docker before lifting the tier.

## Defects of the C original fixed here (all verified by reading it)
1. Base 0 or 1 reachable through `exclude` (division by zero, endless loop): base must be >= 2.
2. Encode buffer `bin_len*2+16` overflows for small bases: output is a `Vec`, sized by the algorithm.
3. Empty input left `enc_data` uninitialised: an empty payload is an empty Data field.
4. All-zero input emitted one symbol too many (decode returned an extra byte, its own output failed):
   n zero bytes are exactly n `alphabet[0]` symbols.
5. Header/config/meta silently truncated on decode and config on encode: lengths are checked, errors returned.
6. `]` in header/meta, and non-alphabet characters in `exclude`, broke framing: rejected.
7. Trailing data and an unterminated meta were accepted: rejected (the `[Meta]` section is required).
8. Quadratic decode on hostile input: total frame length is capped at 16 KiB, payload at 4 KiB.
9. `exclude` must be canonical (strictly ascending ASCII, unique, inside the alphabet, no `|`), so one
   payload has one encoding.
10. The 4-byte checksum detects accidents only. It is not a MAC or signature.
