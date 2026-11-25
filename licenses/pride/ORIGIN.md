# pride: port from Python

- Original URL: https://github.com/obfusk/pypride
- Original commit: 97d724c086a0f498bdd049ddaf0b6f9e30822492
- Original license: LGPL-3.0-or-later (see LICENSE in this folder)
- Original language: Python 3 (also runs on 2)
- Original file(s): pypride.py
- Manifest row: 183 (collection/MANIFEST.csv)
- Algorithm: PRIDE (CRYPTO 2014), 64-bit block, 128-bit key, 20 rounds (the original's default). Identity checked against the source (structure, tables and constants follow the specification) before porting.
- Port: `port/pride.c`, `port/pride.h`. Line-by-line translation, no redesign. Deviations forced by the language: fixed-width C integers
  and byte arrays instead of Python integers/lists, tables built or copied literally, and (HITAG2 only) the returned big integer written as bytes.
- Tier: unverified. Reachable only through `nextssl_root_*`. Only an independent review can lift it (hard rule 1).
- Differential test (2026-11-09): original Python vs this C port, Docker image `nextssl-test`, `--network none`, a disposable copy under
  D:\Dev\kat_work\port_ws (the original was never run on the host). Published vectors: 15/15 pass.
  Random inputs: 3120/3120 identical to the original, mismatches 0. The C port was built with
  `-Wall -Wextra -Werror -fsanitize=undefined -fno-sanitize-recover`. Harness: D:\Dev\kat_work\port_ws\diff.py.
