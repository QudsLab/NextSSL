# hitag2: port from Python

- Original URL: https://github.com/jackiecan/hitag2
- Original commit: 0246bb75fa264263d8aec6d6de70de959a1c2cf8
- Original license: NOASSERTION (see LICENSE in this folder)
- Original language: Python 3
- Original file(s): hitag.py
- Manifest row: 1059 (collection/MANIFEST.csv)
- Algorithm: HITAG2 (NXP RFID stream cipher), 48-bit key, 32-bit uid + 32-bit nonce, 48-bit LFSR. Identity checked against the source (structure, tables and constants follow the specification) before porting.
- Port: `port/hitag2.c`, `port/hitag2.h`. Line-by-line translation, no redesign. Deviations forced by the language: fixed-width C integers
  and byte arrays instead of Python integers/lists, tables built or copied literally, and (HITAG2 only) the returned big integer written as bytes.
- Tier: unverified. Reachable only through `nextssl_root_*`. Only an independent review can lift it (hard rule 1).
- Differential test (2026-11-09): original Python vs this C port, Docker image `nextssl-test`, `--network none`, a disposable copy under
  D:\Dev\kat_work\port_ws (the original was never run on the host). Published vectors: 0/0 pass.
  Random inputs: 3000/3000 identical to the original, mismatches 0. The C port was built with
  `-Wall -Wextra -Werror -fsanitize=undefined -fno-sanitize-recover`. Harness: D:\Dev\kat_work\port_ws\diff.py.
