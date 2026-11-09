# KAT provenance: schnorr-bip340

The official BIP 340 test vector table, converted row by row to JSON by a script (no value typed by hand, none produced by the crate under test).

Sources (downloaded 2026-11-08):
- bip-0340/test-vectors.csv (bitcoin/bips, master, downloaded 2026-11-08)
  - URL: https://raw.githubusercontent.com/bitcoin/bips/master/bip-0340/test-vectors.csv
  - sha256: 34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d

Subset rule: none, all 19 rows are used (8 signing vectors replayed exactly, 9 must verify, 10 must be rejected).
