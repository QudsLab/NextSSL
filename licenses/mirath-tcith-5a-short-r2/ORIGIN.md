# ORIGIN: mirath-tcith-5a-short-r2

- package: Mirath round 2 mirath_tcith_5a_short
- source URL: https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-2/submission-pkg/mirath-submission-round2.zip
- file: mirath-submission-round2.zip
- sha256: 13efd6c28c38f9233074119192def715e62d80e888b216cb71b28d8a5a766d39
- subtree: mirath/Reference_Implementation
- parameter set directory: mirath_tcith/mirath_tcith_5a_short
- copied verbatim (whole subtree incl. shared include dirs) by wire batch 10
- license: NOASSERTION

## Support files restored (fix156)

The wire-10 copy dropped files of common/. Restored verbatim from the same zip (sha256 13efd6c2...6d39), subtree mirath/Reference_Implementation/mirath_tcith/mirath_tcith_5a_short/common/
(KeccakP-1600-opt64.c, KeccakP-1600-64.macros, unrolling macros, SnP-Relaned.h, align/brg_endian headers, random.c ...). Nothing edited.
build.rs compiles common/KeccakP-1600-opt64.c (the portable 64-bit Keccak permutation).
